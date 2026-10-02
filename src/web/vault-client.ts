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

import { bs, fromBase64Url, randomBytes, sha256, toBase64Url, utf8 } from '../bytes.js';
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

  wrapKey(raw32: Uint8Array, kek?: CryptoKey): Promise<string>;
  unwrapKey(wrapped: string, kek?: CryptoKey): Promise<Uint8Array>;

  getOrCreateMeshKey(): Promise<MeshKey>;
  /** Devuelve el share de recuperacion (x=2) UNA sola vez; luego lanza SHARE_ALREADY_SHOWN. */
  exportRecoveryShare(): Promise<{ recoveryShare: DEKShare; cloudShare: DEKShare }>;
  /** Reconstruye la meshKey con el share de recuperacion + el share del dispositivo. */
  recoverMeshKey(recoveryShare: DEKShare): Promise<Uint8Array>;
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
  try {
    const pt = await subtle().decrypt(
      { name: 'AES-GCM', iv: bs(fromBase64Url(parts[1])) },
      kek,
      bs(fromBase64Url(parts[2])),
    );
    return new Uint8Array(pt);
  } catch {
    throw new VaultError('BAD_KEY', 'no se pudo desenvolver la clave (KEK incorrecta o datos alterados)');
  }
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
      if (wrapped) await unwrapWith(wrapped, candidate);
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

    async getOrCreateMeshKey() {
      const k = needKek();
      const wrapped = await get<string>('meshKeyWrapped');
      if (wrapped) return toMeshKey(await unwrapWith(wrapped, k));
      const raw = randomBytes(32);
      await put('meshKeyWrapped', await wrapWith(raw, k));
      return toMeshKey(raw);
    },

    async exportRecoveryShare() {
      const { raw } = await self.getOrCreateMeshKey();
      if (await get<boolean>('recoveryShown'))
        throw new VaultError('SHARE_ALREADY_SHOWN', 'el share de recuperacion ya se mostro y no puede repetirse');
      const [device, recoveryShare, cloudShare] = splitDEK(raw);
      await put('deviceShare', device); // un solo share no revela nada (umbral 2)
      await put('recoveryShown', true);
      return { recoveryShare, cloudShare };
    },

    async recoverMeshKey(recoveryShare) {
      const device = await get<DEKShare>('deviceShare');
      if (!device) throw new VaultError('NO_MESH_KEY', 'no hay share de dispositivo');
      return reconstructDEK([device, recoveryShare]);
    },

    async resetPassphrase(recoveryShare, newPassphrase) {
      const raw = await self.recoverMeshKey(recoveryShare);
      const s = randomBytes(16);
      const newKek = await kekFromPassphrase(newPassphrase, s, iterations);
      await put('kekSalt', s);
      await put('meshKeyWrapped', await wrapWith(raw, newKek));
      kek = newKek;
    },
  };
  return self;
}
