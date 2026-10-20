// web/vault-client.ts — VaultClient para navegador (PWA). Solo WebCrypto + IndexedDB.
// Nunca realiza peticiones de red. Nada sale del dispositivo salvo lo que el llamador decida
// hacer con el share de recuperacion o con la meshKey.
//
// Modelo de claves:
//   * identidad de dispositivo: ECDSA P-256, CryptoKey NO extraible guardada en IndexedDB.
//   * KEK (AES-GCM, no extraible): derivada de passphrase (PBKDF2-SHA256) o de passkey PRF (HKDF).
//   * meshKey (32 bytes): se guarda siempre envuelta (AES-GCM) con la KEK.
//   * recuperacion: Shamir 2-de-3 sobre la meshKey; share 1 queda en el dispositivo,
//     share 2 se muestra una sola vez al usuario, share 3 se devuelve para custodia opcional.

import { bs, concatBytes, fromBase64Url, randomBytes, sha256, toBase64Url, utf8 } from '../bytes.js';
import { reconstructDEK, splitDEK, type DEKShare } from '../sealedPack.js';

export const MIN_PBKDF2_ITERATIONS = 310_000;
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;

export class VaultError extends Error {
  constructor(
    public code: 'LOCKED' | 'BAD_KEY' | 'BAD_FORMAT' | 'NO_PASSKEY' | 'SHARE_ALREADY_SHOWN' | 'NO_MESH_KEY' | 'BAD_PARAMS',
    message: string,
  ) {
    super(message);
    this.name = 'VaultError';
  }
}

/** Proveedor de salida PRF de un passkey (inyectable; por defecto usa WebAuthn). */
export interface PasskeyPrfProvider {
  /** Devuelve >=32 bytes deterministas para `salt`, o lanza si el autenticador no soporta PRF. */
  getPrfOutput(salt: Uint8Array): Promise<Uint8Array>;
}

export interface VaultClientOptions {
  storage: 'idb';
  dbName?: string;
  pbkdf2Iterations?: number;
  passkey?: PasskeyPrfProvider;
  /** Para WebAuthn por defecto. */
  rpId?: string;
}

export interface DeviceIdentity {
  deviceId: string;
  /** SPKI en base64url. */
  publicKey: string;
  publicKeyJwk: JsonWebKey;
}

export type UnlockOptions = { passphrase: string } | { passkey: true };

export interface MeshKey {
  /** Bytes crudos (32). Evita retenerlos mas de lo necesario. */
  raw: Uint8Array;
  /** CryptoKey AES-GCM no extraible, derivada de los mismos bytes. */
  key: CryptoKey;
}

export interface VaultClient {
  getDeviceIdentity(): Promise<DeviceIdentity>;
  sign(data: Uint8Array): Promise<Uint8Array>;
  verify(publicKeyJwk: JsonWebKey, data: Uint8Array, signature: Uint8Array): Promise<boolean>;

  /** Disponibilidad probable de passkeys (la confirmacion de PRF solo ocurre al usarlo). */
  isPasskeyPrfAvailable(): boolean;
  /** Deriva la KEK (passphrase o passkey PRF) y la mantiene en memoria. */
  unlock(opts: UnlockOptions): Promise<void>;
  /** Como unlock, pero con passkey si hay soporte; si no, usa passphrase. */
  unlockPreferPasskey(passphrase: string): Promise<'passkey' | 'passphrase'>;
  lock(): void;
  isUnlocked(): boolean;

  /** does not survive resetPassphrase; use wrapBytes for durable secrets */
  wrapKey(raw32: Uint8Array, kek?: CryptoKey): Promise<string>;
  /** does not survive resetPassphrase; use wrapBytes for durable secrets */
  unwrapKey(wrapped: string, kek?: CryptoKey): Promise<Uint8Array>;

  wrapBytes(raw: Uint8Array): Promise<string>;
  unwrapBytes(wrapped: string): Promise<Uint8Array>;

  getOrCreateMeshKey(): Promise<MeshKey>;
  rotateMeshKey(): Promise<{ raw: Uint8Array; epoch: number }>;
  getEpoch(): Promise<number>;
  /** Devuelve el share de recuperacion (x=2) UNA sola vez, salvo que se use reissue: true; luego lanza SHARE_ALREADY_SHOWN. */
  exportRecoveryShare(opts?: { reissue?: boolean }): Promise<{ recoveryShare: DEKShare; cloudShare: DEKShare }>;
  /** Reconstruye la meshKey con el share de recuperacion + el share del dispositivo. */
  recoverMeshKey(recoveryShare: DEKShare): Promise<Uint8Array>;
  /**
   * Reconstruye la meshKey sin el dispositivo, a partir de dos de los tres shares.
   */
  recoverMeshKeyFromShares(a: DEKShare, b: DEKShare): Promise<Uint8Array>;
  /**
   * Importa o reemplaza la meshKey.
   */
  importMeshKey(raw: Uint8Array, opts?: { replace?: boolean }): Promise<void>;
  /** Recupera la meshKey y la re-envuelve con una nueva passphrase. */
  resetPassphrase(recoveryShare: DEKShare, newPassphrase: string): Promise<void>;
}

// ── IndexedDB mini wrapper ────────────────────────────────────────────────────

const STORE = 'kv';

function openDb(name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(name, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx<T>(db: IDBDatabase, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const r = fn(t.objectStore(STORE));
    t.oncomplete = () => resolve(r.result);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  });
}

// ── Primitivas ────────────────────────────────────────────────────────────────

const subtle = () => globalThis.crypto.subtle;

async function kekFromPassphrase(passphrase: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const base = await subtle().importKey('raw', bs(utf8(passphrase.normalize('NFKC'))), 'PBKDF2', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: bs(salt), iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function kekFromPrf(prf: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  const base = await subtle().importKey('raw', bs(prf), 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: bs(salt), info: bs(utf8('swal-vault/kek/v1')) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Formato: "v1.<iv b64url>.<ct+tag b64url>" */
async function wrapWith(raw: Uint8Array, kek: CryptoKey): Promise<string> {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: bs(iv) }, kek, bs(raw)));
  return `v1.${toBase64Url(iv)}.${toBase64Url(ct)}`;
}

async function unwrapWith(wrapped: string, kek: CryptoKey): Promise<Uint8Array> {
  const parts = wrapped.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') throw new VaultError('BAD_FORMAT', 'formato de clave envuelta invalido');
  let iv: Uint8Array;
  try {
    iv = fromBase64Url(parts[1]);
  } catch {
    throw new VaultError('BAD_FORMAT', 'iv invalido');
  }
  if (iv.length !== 12) throw new VaultError('BAD_FORMAT', 'iv invalido');
  try {
    const pt = await subtle().decrypt(
      { name: 'AES-GCM', iv: bs(iv) },
      kek,
      bs(fromBase64Url(parts[2])),
    );
    return new Uint8Array(pt);
  } catch {
    throw new VaultError('BAD_KEY', 'no se pudo desenvolver la clave (KEK incorrecta o datos alterados)');
  }
}

async function computeMeshKeyCheck(raw: Uint8Array): Promise<string> {
  return toBase64Url(await sha256(concatBytes(utf8('swal-vault/mesh-check/v1'), raw)));
}

type Kv = {
  get: <T>(k: string) => Promise<T | undefined>;
  put: (k: string, v: unknown) => Promise<void>;
};

function defaultPasskeyProvider(kv: Kv, rpId?: string): PasskeyPrfProvider | undefined {
  if (typeof PublicKeyCredential === 'undefined' || !globalThis.navigator?.credentials) return undefined;
  return {
    async getPrfOutput(salt) {
      const cred = globalThis.navigator.credentials;
      const idRaw = await kv.get<Uint8Array>('passkeyCredId');
      const ext = { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs;
      let credential: PublicKeyCredential | null;
      if (!idRaw) {
        credential = (await cred.create({
          publicKey: {
            rp: { name: 'SWAL Vault', ...(rpId ? { id: rpId } : {}) },
            user: { id: bs(randomBytes(16)), name: 'swal-vault', displayName: 'SWAL Vault' },
            challenge: bs(randomBytes(32)),
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
            authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
            extensions: { prf: {} } as AuthenticationExtensionsClientInputs,
          },
        })) as PublicKeyCredential | null;
        if (!credential) throw new VaultError('NO_PASSKEY', 'creacion de passkey cancelada');
        if (!(credential.getClientExtensionResults() as any).prf?.enabled)
          throw new VaultError('NO_PASSKEY', 'el autenticador no soporta PRF');
        await kv.put('passkeyCredId', new Uint8Array(credential.rawId));
      }
      const id = (await kv.get<Uint8Array>('passkeyCredId'))!;
      const asr = (await cred.get({
        publicKey: {
          challenge: bs(randomBytes(32)),
          allowCredentials: [{ type: 'public-key', id: bs(id) }],
          userVerification: 'required',
          extensions: ext,
          ...(rpId ? { rpId } : {}),
        },
      })) as PublicKeyCredential | null;
      const first = (asr?.getClientExtensionResults() as any)?.prf?.results?.first as ArrayBuffer | undefined;
      if (!first) throw new VaultError('NO_PASSKEY', 'el passkey no devolvio salida PRF');
      return new Uint8Array(first);
    },
  };
}

// ── Fabrica ───────────────────────────────────────────────────────────────────

export function createVaultClient(opts: VaultClientOptions): VaultClient {
  if (opts.storage !== 'idb') throw new VaultError('BAD_PARAMS', "solo storage: 'idb' esta soportado");
  const iterations = opts.pbkdf2Iterations ?? DEFAULT_PBKDF2_ITERATIONS;
  if (iterations < MIN_PBKDF2_ITERATIONS)
    throw new VaultError('BAD_PARAMS', `pbkdf2Iterations debe ser >= ${MIN_PBKDF2_ITERATIONS}`);
  const dbName = opts.dbName ?? 'swal-vault';

  let dbp: Promise<IDBDatabase> | null = null;
  const db = () => (dbp ??= openDb(dbName));
  const get = async <T>(k: string): Promise<T | undefined> => (await tx(await db(), 'readonly', (s) => s.get(k))) as T | undefined;
  const put = async (k: string, v: unknown): Promise<void> => {
    await tx(await db(), 'readwrite', (s) => s.put(v, k));
  };
  const del = async (k: string): Promise<void> => {
    await tx(await db(), 'readwrite', (s) => s.delete(k));
  };

  const passkey = opts.passkey ?? defaultPasskeyProvider({ get, put }, opts.rpId);

  let kek: CryptoKey | null = null;
  const needKek = (k?: CryptoKey): CryptoKey => {
    const v = k ?? kek;
    if (!v) throw new VaultError('LOCKED', 'vault bloqueado: llama unlock() primero');
    return v;
  };

  async function salt(): Promise<Uint8Array> {
    let s = await get<Uint8Array>('kekSalt');
    if (!s) {
      s = randomBytes(16);
      await put('kekSalt', s);
    }
    return s;
  }

  async function deriveKek(o: UnlockOptions): Promise<CryptoKey> {
    const s = await salt();
    if ('passkey' in o) {
      if (!passkey) throw new VaultError('NO_PASSKEY', 'passkeys no disponibles en este entorno');
      return kekFromPrf(await passkey.getPrfOutput(s), s);
    }
    return kekFromPassphrase(o.passphrase, s, iterations);
  }

  async function toMeshKey(raw: Uint8Array): Promise<MeshKey> {
    const key = await subtle().importKey('raw', bs(raw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    return { raw, key };
  }

  let mutexLock = Promise.resolve();
  async function mutex<T>(fn: () => Promise<T>): Promise<T> {
    const previous = mutexLock;
    let resolveLock!: () => void;
    mutexLock = new Promise((r) => { resolveLock = r; });
    await previous.catch(() => {});
    try {
      return await fn();
    } finally {
      resolveLock();
    }
  }

  const self: VaultClient = {
    async getDeviceIdentity() {
      let pair = await get<CryptoKeyPair>('deviceKeyPair');
      if (!pair) {
        pair = (await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])) as CryptoKeyPair;
        await put('deviceKeyPair', pair);
      }
      const spki = new Uint8Array(await subtle().exportKey('spki', pair.publicKey));
      const publicKeyJwk = await subtle().exportKey('jwk', pair.publicKey);
      return {
        deviceId: toBase64Url((await sha256(spki)).subarray(0, 16)),
        publicKey: toBase64Url(spki),
        publicKeyJwk,
      };
    },

    async sign(data) {
      await self.getDeviceIdentity();
      const pair = (await get<CryptoKeyPair>('deviceKeyPair'))!;
      return new Uint8Array(await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, bs(data)));
    },

    async verify(jwk, data, signature) {
      const key = await subtle().importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      return subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, key, bs(signature), bs(data));
    },

    isPasskeyPrfAvailable: () => !!passkey,

    async unlock(o) {
      const candidate = await deriveKek(o);
      // Si ya existe meshKey, valida la KEK (falla con BAD_KEY si es incorrecta).
      const wrapped = await get<string>('meshKeyWrapped');
      if (wrapped) {
        const raw = await unwrapWith(wrapped, candidate);
        const check = await get<string>('meshKeyCheck');
        if (!check) {
          const newCheck = await computeMeshKeyCheck(raw);
          await new Promise<void>((resolve, reject) => {
            db().then((dbInstance) => {
              const t = dbInstance.transaction(STORE, 'readwrite');
              const s = t.objectStore(STORE);
              t.oncomplete = () => resolve();
              t.onerror = () => reject(t.error);
              t.onabort = () => reject(t.error);

              const mkwReq = s.get('meshKeyWrapped');
              mkwReq.onsuccess = () => {
                if (mkwReq.result !== wrapped) {
                  t.abort();
                  reject(new VaultError('BAD_KEY', 'la clave cambio concurrentemente'));
                  return;
                }
                const chkReq = s.get('meshKeyCheck');
                chkReq.onsuccess = () => {
                  if (!chkReq.result) {
                    try {
                      s.put(newCheck, 'meshKeyCheck');
                    } catch (e) {
                      t.abort();
                      reject(e);
                    }
                  } else {
                     t.oncomplete = () => resolve();
                  }
                };
              };
            }).catch(reject);
          });
        }
      }
      kek = candidate;
    },

    async unlockPreferPasskey(passphrase) {
      if (passkey) {
        try {
          await self.unlock({ passkey: true });
          return 'passkey';
        } catch (e) {
          if (!(e instanceof VaultError) || e.code !== 'NO_PASSKEY') {
            // cancelacion del usuario u otro error de WebAuthn: cae a passphrase
          }
        }
      }
      await self.unlock({ passphrase });
      return 'passphrase';
    },

    lock() {
      kek = null;
    },
    isUnlocked: () => kek !== null,

    wrapKey: (raw32, k) => {
      if (raw32.length !== 32) throw new VaultError('BAD_PARAMS', 'se esperan 32 bytes');
      return wrapWith(raw32, needKek(k));
    },
    unwrapKey: (wrapped, k) => unwrapWith(wrapped, needKek(k)),

    wrapBytes: async (raw) => {
      needKek(); // Ensure unlocked
      if (!(raw instanceof Uint8Array) || raw.byteLength === 0 || raw.byteLength > 65536) throw new VaultError('BAD_PARAMS', 'se esperan de 1 a 65536 bytes');
      const meshKey = await self.getOrCreateMeshKey();
      return mutex(async () => {
        const secretsKeyWrapped = await get<string>('secretsKeyWrapped');
        if (!secretsKeyWrapped) throw new VaultError('BAD_KEY', 'no hay secretsKeyWrapped');
        const secretsKeyBytes = await unwrapWith(secretsKeyWrapped, meshKey.key);
        const secretsKey = await subtle().importKey('raw', bs(secretsKeyBytes), { name: 'AES-GCM' }, false, ['encrypt']);
        return wrapWith(raw, secretsKey);
      });
    },
    unwrapBytes: async (wrapped) => {
      const k = needKek(); // Ensure unlocked
      if (typeof wrapped !== 'string') throw new VaultError('BAD_FORMAT', 'wrapped debe ser un string');

      const parts = wrapped.split('.');
      if (parts.length !== 3 || parts[0] !== 'v1') throw new VaultError('BAD_FORMAT', 'formato de clave envuelta invalido');
      let iv: Uint8Array;
      try {
        iv = fromBase64Url(parts[1]);
      } catch {
        throw new VaultError('BAD_FORMAT', 'iv invalido');
      }
      if (iv.length !== 12) throw new VaultError('BAD_FORMAT', 'iv invalido');

      const [meshKeyWrapped, secretsKeyWrapped] = await new Promise<[string | undefined, string | undefined]>((resolve, reject) => {
        db().then((dbInstance) => {
          const t = dbInstance.transaction(STORE, 'readonly');
          const s = t.objectStore(STORE);
          let mkw: string | undefined;
          let skw: string | undefined;
          const req1 = s.get('meshKeyWrapped');
          req1.onsuccess = () => {
            mkw = req1.result;
            const req2 = s.get('secretsKeyWrapped');
            req2.onsuccess = () => {
              skw = req2.result;
              resolve([mkw, skw]);
            };
            req2.onerror = () => reject(req2.error);
          };
          req1.onerror = () => reject(req1.error);
        }).catch(reject);
      });

      if (!meshKeyWrapped) throw new VaultError('BAD_KEY', 'vault esta vacio o KEK incorrecta');
      if (!secretsKeyWrapped) throw new VaultError('BAD_KEY', 'no hay secretsKeyWrapped');

      const meshKeyRaw = await unwrapWith(meshKeyWrapped, k);
      const meshKey = await toMeshKey(meshKeyRaw);

      const secretsKeyBytes = await unwrapWith(secretsKeyWrapped, meshKey.key);
      const secretsKey = await subtle().importKey('raw', bs(secretsKeyBytes), { name: 'AES-GCM' }, false, ['decrypt']);
      return unwrapWith(wrapped, secretsKey);
    },

    async getEpoch() {
      return (await get<number>('epoch')) ?? 0;
    },

    async rotateMeshKey() {
      return mutex(async () => {
        const k = needKek();
        const oldWrapped = await get<string>('meshKeyWrapped');
        const oldMeshKey = oldWrapped ? await toMeshKey(await unwrapWith(oldWrapped, k)) : null;

        const raw = randomBytes(32);
        const wrapped = await wrapWith(raw, k);
        const newMeshKey = await toMeshKey(raw);
        const check = await computeMeshKeyCheck(raw);

        let newSecretsKeyWrapped: string | null = null;
        if (oldMeshKey) {
          const secretsKeyWrapped = await get<string>('secretsKeyWrapped');
          if (secretsKeyWrapped) {
            const secretsKeyBytes = await unwrapWith(secretsKeyWrapped, oldMeshKey.key);
            newSecretsKeyWrapped = await wrapWith(secretsKeyBytes, newMeshKey.key);
          }
        }

        return new Promise((resolve, reject) => {
          db().then((dbInstance) => {
            const t = dbInstance.transaction(STORE, 'readwrite');
            const s = t.objectStore(STORE);
            t.onerror = () => reject(t.error);
            t.onabort = () => reject(t.error);

            const getWrappedReq = s.get('meshKeyWrapped');
            getWrappedReq.onsuccess = () => {
              if (getWrappedReq.result !== oldWrapped) {
                t.abort();
                reject(new VaultError('BAD_KEY', 'la clave cambio concurrentemente'));
                return;
              }

              const getEpochReq = s.get('epoch');
              getEpochReq.onsuccess = () => {
                const epoch = (getEpochReq.result || 0) + 1;
                try {
                  s.put(wrapped, 'meshKeyWrapped');
                  s.put(check, 'meshKeyCheck');
                  s.put(epoch, 'epoch');
                  s.put(false, 'recoveryShown');
                  s.delete('deviceShare');
                  if (newSecretsKeyWrapped) {
                    s.put(newSecretsKeyWrapped, 'secretsKeyWrapped');
                  }
                } catch (e) {
                  t.abort();
                  reject(e);
                  return;
                }
                t.oncomplete = () => resolve({ raw, epoch });
              };
              getEpochReq.onerror = () => {
                t.abort();
                reject(getEpochReq.error);
              };
            };
            getWrappedReq.onerror = () => {
              t.abort();
              reject(getWrappedReq.error);
            };
          }).catch(reject);
        });
      });
    },

    async getOrCreateMeshKey() {
      return mutex(async () => {
        const k = needKek();
        let wrapped = await get<string>('meshKeyWrapped');
        let meshKeyRaw: Uint8Array;
        let lost = false;
        if (wrapped) {
          meshKeyRaw = await unwrapWith(wrapped, k);
        } else {
          meshKeyRaw = randomBytes(32);
          wrapped = await wrapWith(meshKeyRaw, k);
          const check = await computeMeshKeyCheck(meshKeyRaw);

          await new Promise<void>((resolve, reject) => {
            db().then((dbInstance) => {
              const t = dbInstance.transaction(STORE, 'readwrite');
              const s = t.objectStore(STORE);
              t.onerror = () => reject(t.error);
              t.onabort = () => reject(t.error);

              const getWrappedReq = s.get('meshKeyWrapped');
              getWrappedReq.onsuccess = () => {
                if (getWrappedReq.result) {
                  // Ya se creó concurrentemente
                  lost = true;
                  wrapped = getWrappedReq.result;
                  resolve();
                } else {
                  try {
                    s.put(wrapped, 'meshKeyWrapped');
                    s.put(check, 'meshKeyCheck');
                  } catch (e) {
                    t.abort();
                    reject(e);
                  }
                  t.oncomplete = () => resolve();
                }
              };
              getWrappedReq.onerror = () => {
                t.abort();
                reject(getWrappedReq.error);
              };
            }).catch(reject);
          });

          if (lost) {
             meshKeyRaw = await unwrapWith(wrapped, k);
          }
        }
        const meshKey = await toMeshKey(meshKeyRaw);

        let secretsKeyWrapped = await get<string>('secretsKeyWrapped');
        if (!secretsKeyWrapped) {
          const secretsKeyRaw = randomBytes(32);
          const newSecretsKeyWrapped = await wrapWith(secretsKeyRaw, meshKey.key);
          await new Promise<void>((resolve, reject) => {
            db().then((dbInstance) => {
              const t = dbInstance.transaction(STORE, 'readwrite');
              const s = t.objectStore(STORE);
              t.onerror = () => reject(t.error);
              t.onabort = () => reject(t.error);

              const mkwReq = s.get('meshKeyWrapped');
              mkwReq.onsuccess = () => {
                if (mkwReq.result !== wrapped) {
                   t.abort();
                   reject(new VaultError('BAD_KEY', 'la clave cambio concurrentemente'));
                   return;
                }

                const getSecretsReq = s.get('secretsKeyWrapped');
                getSecretsReq.onsuccess = () => {
                  if (!getSecretsReq.result) {
                    try {
                      s.put(newSecretsKeyWrapped, 'secretsKeyWrapped');
                    } catch (e) {
                      t.abort();
                      reject(e);
                    }
                  }
                  t.oncomplete = () => resolve();
                };
                getSecretsReq.onerror = () => {
                  t.abort();
                  reject(getSecretsReq.error);
                };
              };
              mkwReq.onerror = () => {
                t.abort();
                reject(mkwReq.error);
              };
            }).catch(reject);
          });
        }

        return meshKey;
      });
    },

    async exportRecoveryShare(opts) {
      const reissue = opts?.reissue ?? false;
      if (reissue) {
        needKek();
      }
      // Must read wrapped first, then split the exact key that we checked against.
      // We get both to ensure the raw key we split is derived from the exact wrapped string we assert on.
      const k = needKek();
      let wrappedRef = await get<string>('meshKeyWrapped');
      if (!wrappedRef) {
        await self.getOrCreateMeshKey();
        wrappedRef = (await get<string>('meshKeyWrapped'))!;
      }
      // Unwrap directly so we KNOW these raw bytes belong to this specific wrapped string
      const raw = await unwrapWith(wrappedRef, k);
      const [device, recoveryShare, cloudShare] = splitDEK(raw);

      return new Promise((resolve, reject) => {
        db().then((dbInstance) => {
          const t = dbInstance.transaction(STORE, 'readwrite');
          const s = t.objectStore(STORE);
          t.onerror = () => reject(t.error);
          t.onabort = () => reject(t.error);

          const getWrappedReq = s.get('meshKeyWrapped');
          getWrappedReq.onsuccess = () => {
            // If the key changed during the export logic, abort to prevent writing a stale deviceShare.
            if (getWrappedReq.result !== wrappedRef) {
              t.abort();
              reject(new VaultError('BAD_KEY', 'la clave cambio durante la exportacion'));
              return;
            }
            // For race condition handling, if rotation finished *before* we read, then
            // wrappedRef already captures the rotated key and we are safe.
            // If rotation finishes *after* we evaluate the above condition but *before* we put the share,
            // the IndexedDB readwrite transaction serialization guarantees we hold the store.
            if (!reissue) {
              const getShownReq = s.get('recoveryShown');
              getShownReq.onsuccess = () => {
                if (getShownReq.result) {
                  t.abort();
                  reject(new VaultError('SHARE_ALREADY_SHOWN', 'el share de recuperacion ya se mostro y no puede repetirse'));
                  return;
                }
                s.put(device, 'deviceShare');
                s.put(true, 'recoveryShown');
                t.oncomplete = () => resolve({ recoveryShare, cloudShare });
              };
              getShownReq.onerror = () => {
                t.abort();
                reject(getShownReq.error);
              };
            } else {
              s.put(device, 'deviceShare');
              s.put(true, 'recoveryShown');
              t.oncomplete = () => resolve({ recoveryShare, cloudShare });
            }
          };
          getWrappedReq.onerror = () => {
            t.abort();
            reject(getWrappedReq.error);
          };
        }).catch(reject);
      });
    },

    async recoverMeshKey(recoveryShare) {
      const device = await get<DEKShare>('deviceShare');
      if (!device) throw new VaultError('NO_MESH_KEY', 'no hay share de dispositivo');
      if (!recoveryShare || typeof recoveryShare.value !== 'string') {
        throw new VaultError('BAD_FORMAT', 'los shares deben contener un valor string');
      }
      try {
        return reconstructDEK([device, recoveryShare]);
      } catch {
        throw new VaultError('BAD_FORMAT', 'formato de share invalido al reconstruir la clave');
      }
    },

    async recoverMeshKeyFromShares(a, b) {
      needKek();
      if (!a || !b || typeof a.value !== 'string' || typeof b.value !== 'string') {
        throw new VaultError('BAD_FORMAT', 'los shares deben contener un valor string');
      }
      if (!Number.isInteger(a.index) || !Number.isInteger(b.index) || a.index < 1 || a.index > 3 || b.index < 1 || b.index > 3) {
        throw new VaultError('BAD_PARAMS', 'los indices de los shares deben ser enteros entre 1 y 3');
      }
      if (a.index === b.index) {
        throw new VaultError('BAD_PARAMS', 'los indices de los shares deben ser diferentes');
      }
      try {
        return reconstructDEK([a, b]);
      } catch {
        throw new VaultError('BAD_FORMAT', 'formato de share invalido al reconstruir la clave');
      }
    },

    async importMeshKey(raw, opts) {
      return mutex(async () => {
        const k = needKek();
        if (!(raw instanceof Uint8Array)) throw new VaultError('BAD_PARAMS', 'raw debe ser Uint8Array');
        if (raw.length !== 32) throw new VaultError('BAD_PARAMS', 'se esperan 32 bytes para la meshKey');

        const oldWrapped = await get<string>('meshKeyWrapped');
        const oldMeshKey = oldWrapped ? await toMeshKey(await unwrapWith(oldWrapped, k)) : null;

        const wrapped = await wrapWith(raw, k);
        const check = await computeMeshKeyCheck(raw);
        const newMeshKey = await toMeshKey(raw);

        let newSecretsKeyWrapped: string | null = null;
        if (oldMeshKey && opts?.replace) {
           const secretsKeyWrapped = await get<string>('secretsKeyWrapped');
           if (secretsKeyWrapped) {
              const secretsKeyBytes = await unwrapWith(secretsKeyWrapped, oldMeshKey.key);
              newSecretsKeyWrapped = await wrapWith(secretsKeyBytes, newMeshKey.key);
           }
        }

        return new Promise((resolve, reject) => {
          db().then((dbInstance) => {
            const t = dbInstance.transaction(STORE, 'readwrite');
            const s = t.objectStore(STORE);
            t.onerror = () => reject(t.error);
            t.onabort = () => reject(t.error);

            const getReq = s.get('meshKeyWrapped');
            getReq.onsuccess = () => {
              if (getReq.result && !opts?.replace) {
                t.abort();
                reject(new VaultError('BAD_PARAMS', 'ya existe una clave y replace no es verdadero'));
                return;
              }
              if (getReq.result !== oldWrapped) {
                t.abort();
                reject(new VaultError('BAD_KEY', 'la clave cambio concurrentemente'));
                return;
              }
              try {
                s.put(wrapped, 'meshKeyWrapped');
                s.put(check, 'meshKeyCheck');
                if (opts?.replace) {
                  s.delete('deviceShare');
                  s.delete('recoveryShown');
                  if (newSecretsKeyWrapped) {
                    s.put(newSecretsKeyWrapped, 'secretsKeyWrapped');
                  }
                  const epochReq = s.get('epoch');
                  epochReq.onsuccess = () => {
                    try {
                      s.put((epochReq.result || 0) + 1, 'epoch');
                    } catch (e) {
                      t.abort();
                      reject(e);
                      return;
                    }
                    t.oncomplete = () => resolve();
                  };
                  epochReq.onerror = () => {
                    t.abort();
                    reject(epochReq.error);
                  };
                } else {
                   t.oncomplete = () => resolve();
                }
              } catch (e) {
                t.abort();
                reject(e);
                return;
              }
            };
            getReq.onerror = () => {
              t.abort();
              reject(getReq.error);
            };
          }).catch(reject);
        });
      });
    },

    async resetPassphrase(recoveryShare, newPassphrase) {
      return mutex(async () => {
        const [preDeviceShare, preMeshKeyWrapped, preMeshKeyCheck] = await new Promise<[DEKShare | undefined, string | undefined, string | undefined]>((resolve, reject) => {
          db().then((dbInstance) => {
             const t = dbInstance.transaction(STORE, 'readonly');
             const s = t.objectStore(STORE);
             let ds: DEKShare | undefined;
             let mkw: string | undefined;
             let mkc: string | undefined;
             const r1 = s.get('deviceShare');
             r1.onsuccess = () => {
                ds = r1.result;
                const r2 = s.get('meshKeyWrapped');
                r2.onsuccess = () => {
                   mkw = r2.result;
                   const r3 = s.get('meshKeyCheck');
                   r3.onsuccess = () => {
                      mkc = r3.result;
                      resolve([ds, mkw, mkc]);
                   };
                   r3.onerror = () => reject(r3.error);
                };
                r2.onerror = () => reject(r2.error);
             };
             r1.onerror = () => reject(r1.error);
          }).catch(reject);
        });

        if (!preDeviceShare) throw new VaultError('NO_MESH_KEY', 'no hay share de dispositivo');
        if (!recoveryShare || typeof recoveryShare.value !== 'string') throw new VaultError('BAD_FORMAT', 'los shares deben contener un valor string');

        let raw: Uint8Array;
        try {
          raw = reconstructDEK([preDeviceShare, recoveryShare]);
        } catch {
          throw new VaultError('BAD_FORMAT', 'formato de share invalido al reconstruir la clave');
        }

        const expectedCheck = await computeMeshKeyCheck(raw);
        if (preMeshKeyCheck && preMeshKeyCheck !== expectedCheck) {
          throw new VaultError('BAD_KEY', 'la clave recuperada no coincide con el check almacenado');
        }

        const s = randomBytes(16);
        const newKek = await kekFromPassphrase(newPassphrase, s, iterations);
        const wrapped = await wrapWith(raw, newKek);

        await new Promise<void>((resolve, reject) => {
          db().then((dbInstance) => {
            const t = dbInstance.transaction(STORE, 'readwrite');
            const store = t.objectStore(STORE);
            t.oncomplete = () => resolve();
            t.onerror = () => reject(t.error);
            t.onabort = () => reject(t.error);

            const mkwReq = store.get('meshKeyWrapped');
            mkwReq.onsuccess = () => {
              if (mkwReq.result !== preMeshKeyWrapped) {
                 t.abort();
                 reject(new VaultError('BAD_KEY', 'la clave cambio concurrentemente'));
                 return;
              }
              const devReq = store.get('deviceShare');
              devReq.onsuccess = () => {
                 if (devReq.result?.value !== preDeviceShare.value) {
                    t.abort();
                    reject(new VaultError('BAD_KEY', 'el device share cambio concurrentemente'));
                    return;
                 }
                 const chkReq = store.get('meshKeyCheck');
                 chkReq.onsuccess = () => {
                    if (chkReq.result !== preMeshKeyCheck) {
                        t.abort();
                        reject(new VaultError('BAD_KEY', 'el check cambio concurrentemente'));
                        return;
                    }
                    try {
                      store.put(wrapped, 'meshKeyWrapped');
                      store.put(s, 'kekSalt');
                      store.put(expectedCheck, 'meshKeyCheck');
                    } catch (e) {
                      t.abort();
                      reject(e);
                    }
                 };
                 chkReq.onerror = () => {
                    t.abort();
                    reject(chkReq.error);
                 };
              };
              devReq.onerror = () => {
                 t.abort();
                 reject(devReq.error);
              };
            };
            mkwReq.onerror = () => {
               t.abort();
               reject(mkwReq.error);
            };
          }).catch(reject);
        });

        kek = newKek;
      });
    },
  };
  return self;
}
