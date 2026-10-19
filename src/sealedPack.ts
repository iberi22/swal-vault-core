// sealedPack.ts — core reusable vault (antes en gara-g app-pwa)
// Extraído a cores/swal-vault para reuso en gara-g, hosteler-ia, flota, cualquier app SWAL.
// 100% cifrado: AES-256-GCM + Shamir 2-of-3 sobre DEK + SHA256 content_hash + Ed25519.
// Cloudflare nunca ve plaintext, solo ciphertext+shares+hash.
// Pay-per-use: costo solo si se sube a R2; mesh-only gratis (replica P2P en otros nodos gara-g).

import {
  bs, concatBytes, fromBase64, fromHex, randomBytes, randomInt, sha256, sha256Sync, toBase64, toHex, utf8,
} from './bytes.js';

const subtle = () => globalThis.crypto.subtle;

// Cadena de anclaje por defecto (sin dependencia de @swal/econ-sdk; el vault es puro).
const _econChain = 'polygon';
const _econChainId = 137;

/** Version de formato del pack. Ausente = legado (sin AAD). 2 = metadatos ligados como AAD de AES-GCM. 3 = Shamir sobre GF(2^8). */
export const PACK_VERSION = 3;

/**
 * Lista blanca de metadatos que pueden viajar EN CLARO junto al pack. Todo lo que no este aqui
 * se rechaza al sellar (salvo `extraClearKeys` explicito): los metadatos no van cifrados.
 */
export const CLEAR_METADATA_KEYS: readonly string[] = [
  'vehicleId', 'entityId', 'entity', 'appId', 'instanceId', 'timestamp', 'recordCount', 'deviceId',
];

export interface DEKShare {
  index: number;
  value: string;
  v?: number;
}

export interface SealedPackMetadata {
  vehicleId?: string;
  entityId?: string;
  entity?: string;
  appId?: string;
  instanceId?: string;
  timestamp: number;
  recordCount?: number;
  deviceId?: string;
  // extensible para cualquier modelo negocio: gara-g vehicle, hosteler order, etc.
  [k: string]: unknown;
}

export interface SealedPack {
  /** Version de formato. Ausente = legado sin AAD. */
  v?: number;
  id: string;
  content_hash: string;
  ciphertext: string;
  iv: string;
  tag: string;
  shares: DEKShare[];
  signature: string;
  publicKey: string;
  sigAlg?: 'Ed25519' | 'ECDSA-P256';
  metadata: SealedPackMetadata;
  chain: string;
  chainId: number;
}

function mod257(n: number): number {
  const r = n % 257;
  return r < 0 ? r + 257 : r;
}
function modInverse257(n: number): number {
  const a = mod257(n);
  if (a === 0) throw new Error('Division by zero GF257');
  let res = 1;
  let base = a;
  let exp = 255;
  while (exp > 0) {
    if (exp % 2 === 1) res = (res * base) % 257;
    base = (base * base) % 257;
    exp = Math.floor(exp / 2);
  }
  return res;
}


const exp256 = new Uint8Array(256);
const log256 = new Uint8Array(256);
let _x256 = 1;
for (let i = 0; i < 255; i++) {
  exp256[i] = _x256;
  log256[_x256] = i;
  let x2 = _x256 << 1;
  if (x2 & 0x100) x2 ^= 0x11b;
  _x256 = x2 ^ _x256;
}

function mul256(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return exp256[(log256[a] + log256[b]) % 255];
}
function inv256(a: number): number {
  if (a === 0) throw new Error('Division by zero GF256');
  return exp256[(255 - log256[a]) % 255];
}

export function splitDEK(dek: Uint8Array, version: number = 3): DEKShare[] {
  if (version !== 2 && version !== 3) {
    throw new Error(`Unsupported splitDEK version: ${version}`);
  }
  if (dek.length !== 32) throw new Error('DEK 32 bytes');
  const s1 = new Uint8Array(32);
  const s2 = new Uint8Array(32);
  const s3 = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const secret = dek[i];
    let a1: number, y1: number, y2: number, y3: number;
    if (version === 2) {
      do {
        a1 = randomInt(1, 257);
        y1 = mod257(secret + a1 * 1);
        y2 = mod257(secret + a1 * 2);
        y3 = mod257(secret + a1 * 3);
      } while (y1 === 256 || y2 === 256 || y3 === 256);
    } else {
      a1 = randomInt(0, 256);
      y1 = secret ^ mul256(a1, 1);
      y2 = secret ^ mul256(a1, 2);
      y3 = secret ^ mul256(a1, 3);
    }
    s1[i] = y1;
    s2[i] = y2;
    s3[i] = y3;
  }
  return [
    { index: 1, value: toBase64(s1), v: version },
    { index: 2, value: toBase64(s2), v: version },
    { index: 3, value: toBase64(s3), v: version },
  ];
}

export function reconstructDEK(shares: DEKShare[]): Uint8Array {
  if (shares.length < 2) throw new Error('At least 2 shares are required to reconstruct DEK');
  const s1 = shares[0], s2 = shares[1];
  const v1 = s1.v ?? 2, v2 = s2.v ?? 2;
  if (v1 !== v2) throw new Error('Share versions do not match');
  const version = v1;
  if (version !== 2 && version !== 3) throw new Error(`Unsupported share version: ${version}`);
  const x1 = s1.index, x2 = s2.index;
  if (!Number.isInteger(x1) || !Number.isInteger(x2) || x1 < 1 || x1 > 255 || x2 < 1 || x2 > 255) throw new Error('Invalid share index');
  if (x1 === x2) throw new Error('shares duplicate x');
  const y1 = fromBase64(s1.value);
  const y2 = fromBase64(s2.value);
  if (y1.length !== 32 || y2.length !== 32) throw new Error('share length 32');
  const dek = new Uint8Array(32);
  if (version === 2) {
    const num1 = mod257(-x2), den1 = mod257(x1 - x2), L1 = mod257(num1 * modInverse257(den1));
    const num2 = mod257(-x1), den2 = mod257(x2 - x1), L2 = mod257(num2 * modInverse257(den2));
    for (let i = 0; i < 32; i++) dek[i] = mod257(y1[i] * L1 + y2[i] * L2);
  } else {
    const L1 = mul256(x2, inv256(x1 ^ x2));
    const L2 = mul256(x1, inv256(x1 ^ x2));
    for (let i = 0; i < 32; i++) dek[i] = mul256(y1[i], L1) ^ mul256(y2[i], L2);
  }
  return dek;
}

function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().filter((k) => o[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`;
  }
  return JSON.stringify(v) ?? 'null';
}

/** AAD de AES-GCM (v2): los metadatos quedan autenticados; alterarlos rompe el descifrado. */
function metadataAad(metadata: SealedPackMetadata, version: number): Uint8Array {
  return utf8(`swal-vault/v${version}|${canonicalJson(metadata)}`);
}

function assertMetadataWhitelisted(metadata: SealedPackMetadata, extra: readonly string[]): void {
  const allowed = new Set([...CLEAR_METADATA_KEYS, ...extra]);
  for (const k of Object.keys(metadata)) {
    if (!allowed.has(k)) {
      throw new Error(`Metadato "${k}" no esta en la lista blanca de metadatos en claro (usa extraClearKeys si es intencional)`);
    }
  }
}

function contentHashInput(ciphertext: Uint8Array, metadata: SealedPackMetadata): Uint8Array {
  return concatBytes(ciphertext, utf8(JSON.stringify(metadata, Object.keys(metadata).sort())));
}

/**
 * @deprecated Usa `computeContentHashAsync` (WebCrypto). Se mantiene sincrono (SHA-256 JS puro)
 * solo por compatibilidad; produce el mismo resultado.
 */
export function computeContentHash(ciphertext: Uint8Array, metadata: SealedPackMetadata): string {
  return '0x' + toHex(sha256Sync(contentHashInput(ciphertext, metadata)));
}

export async function computeContentHashAsync(ciphertext: Uint8Array, metadata: SealedPackMetadata): Promise<string> {
  return '0x' + toHex(await sha256(contentHashInput(ciphertext, metadata)));
}

// ── Frontera de confianza: qué NO puede vivir en la nube ─────────────────────────
//
// El reparto es Shamir 2-de-3: con DOS shares cualquiera se reconstruye la DEK. Por tanto la nube
// (R2 + D1 + KV) **nunca** puede acumular 2 shares, o el operador podria leer los datos y la
// promesa "el operador no puede leer" seria falsa.
//
// Reparto correcto:
//   * share x=1 -> DISPOSITIVO (nunca se sube)
//   * share x=2 -> RECUPERACION (nunca se sube; se entrega al usuario en el alta)
//   * share x=3 -> KV (unico share que la nube puede tener)
//
// Asi R2+D1+KV juntos suman 1 share y no alcanzan el umbral.

/** Umbral de Shamir: shares necesarias para reconstruir. */
export const SHAMIR_THRESHOLD = 2;

/** Indice del unico share que puede residir en la nube. */
export const CLOUD_SHARE_INDEX = 3;

/** Devuelve una copia del pack SIN shares, apta para almacenar en la nube. */
export function packWithoutShares(pack: SealedPack): SealedPack {
  return { ...pack, shares: [] };
}

/** El share que puede subirse a KV (x=3). `null` si no existe. */
export function cloudBoundShare(shares: DEKShare[]): DEKShare | null {
  return shares.find((s) => s.index === CLOUD_SHARE_INDEX) ?? null;
}

/**
 * Guarda de la frontera: lanza si la nube acumularia el umbral o mas shares.
 * Se usa antes de subir nada, para fallar cerrado en vez de filtrar la clave.
 */
export function assertCloudSharesSafe(cloudShareCount: number): void {
  if (cloudShareCount >= SHAMIR_THRESHOLD) {
    throw new Error(
      `E2EE: la nube no puede acumular ${cloudShareCount} shares (umbral ${SHAMIR_THRESHOLD}). ` +
        'Deja en el dispositivo los shares 1 y 2 y sube solo el 3.',
    );
  }
}

/**
 * Par de claves Ed25519. Acepta CryptoKeyPair (WebCrypto) o, por compat, el par de
 * `KeyObject` de node (se detecta por duck-typing, sin depender de modulos de node).
 */
export type SealedPackKeyPair =
  | CryptoKeyPair
  | { privateKey: { export(o: { type: 'pkcs8'; format: 'der' }): Uint8Array }; publicKey: { export(o: { type: 'spki'; format: 'der' }): Uint8Array } };

async function resolveKeyPair(kp?: SealedPackKeyPair): Promise<{ priv: CryptoKey; pubSpki: Uint8Array }> {
  if (!kp) {
    const pair = (await subtle().generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    return { priv: pair.privateKey, pubSpki: new Uint8Array(await subtle().exportKey('spki', pair.publicKey)) };
  }
  const priv = kp.privateKey as any;
  if (typeof priv.export === 'function') {
    const pkcs8 = new Uint8Array(priv.export({ type: 'pkcs8', format: 'der' }));
    const pubSpki = new Uint8Array((kp.publicKey as any).export({ type: 'spki', format: 'der' }));
    return { priv: await subtle().importKey('pkcs8', bs(pkcs8), { name: 'Ed25519' }, false, ['sign']), pubSpki };
  }
  return { priv: priv as CryptoKey, pubSpki: new Uint8Array(await subtle().exportKey('spki', kp.publicKey as CryptoKey)) };
}

async function aesKey(dek: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  return subtle().importKey('raw', bs(dek), { name: 'AES-GCM' }, false, [usage]);
}

export async function createSealedPack(
  payload: Uint8Array,
  metadata: SealedPackMetadata,
  keyPair?: SealedPackKeyPair,
  options: {
    extraClearKeys?: string[];
    signer?: { alg: 'Ed25519' | 'ECDSA-P256'; publicKey: Uint8Array; sign(data: Uint8Array): Promise<Uint8Array> };
  } = {},
): Promise<SealedPack> {
  if (keyPair && options.signer) throw new Error('Cannot provide both keyPair and options.signer');
  assertMetadataWhitelisted(metadata, options.extraClearKeys ?? []);
  const dek = randomBytes(32);
  const iv = randomBytes(12);
  // WebCrypto devuelve ciphertext||tag(16); se separan para mantener el formato del pack.
  const sealed = new Uint8Array(
    await subtle().encrypt({ name: 'AES-GCM', iv: bs(iv), tagLength: 128, additionalData: bs(metadataAad(metadata, PACK_VERSION)) }, await aesKey(dek, 'encrypt'), bs(payload)),
  );
  const ct = sealed.subarray(0, sealed.length - 16);
  const tag = sealed.subarray(sealed.length - 16);
  const shares = splitDEK(dek, PACK_VERSION);
  const contentHash = await computeContentHashAsync(ct, metadata);

  let sigAlg: 'Ed25519' | 'ECDSA-P256' | undefined;
  let signatureHex: string;
  let publicKeyHex: string;

  if (options.signer) {
    sigAlg = options.signer.alg;
    publicKeyHex = toHex(options.signer.publicKey);
    signatureHex = toHex(await options.signer.sign(utf8(contentHash)));
  } else {
    const { priv, pubSpki } = await resolveKeyPair(keyPair);
    const sigBytes = new Uint8Array(await subtle().sign({ name: 'Ed25519' }, priv, bs(utf8(contentHash))));
    signatureHex = toHex(sigBytes);
    publicKeyHex = toHex(pubSpki);
  }

  const pack: SealedPack = {
    v: PACK_VERSION,
    id: `pack-${globalThis.crypto.randomUUID()}`,
    content_hash: contentHash,
    ciphertext: toBase64(ct),
    iv: toBase64(iv),
    tag: toBase64(tag),
    shares,
    signature: signatureHex,
    publicKey: publicKeyHex,
    metadata,
    chain: _econChain,
    chainId: _econChainId,
  };
  if (sigAlg) pack.sigAlg = sigAlg;

  // Verify the signature we just created
  if (!(await verifySealedPackSignature(pack))) {
    throw new Error('Generacion de firma invalida');
  }
  return pack;
}

export async function unpackSealedPack(pack: SealedPack, shares: DEKShare[]): Promise<Uint8Array> {
  const packV = pack.v ?? 2;
  if (packV !== 2 && packV !== 3) throw new Error(`Version de pack no soportada: ${pack.v}`);
  if (shares.length > 0 && (shares[0].v ?? 2) !== packV) throw new Error('Share version mismatch');
  const dek = reconstructDEK(shares);
  const ct = fromBase64(pack.ciphertext);
  const iv = fromBase64(pack.iv);
  const tag = fromBase64(pack.tag);
  const params: AesGcmParams = { name: 'AES-GCM', iv: bs(iv), tagLength: 128 };
  if (pack.v !== undefined) params.additionalData = bs(metadataAad(pack.metadata, pack.v));
  const dec = await subtle().decrypt(
    params,
    await aesKey(dek, 'decrypt'),
    bs(concatBytes(ct, tag)),
  );
  return new Uint8Array(dec);
}

export async function verifySealedPackHash(pack: SealedPack): Promise<boolean> {
  const exp = await computeContentHashAsync(fromBase64(pack.ciphertext), pack.metadata);
  return exp.toLowerCase() === pack.content_hash.toLowerCase();
}

/** Verifica la firma del content_hash con la publicKey del pack. */
export async function verifySealedPackSignature(pack: SealedPack, pinnedPublicKeys?: string[]): Promise<boolean> {
  if (pinnedPublicKeys && !pinnedPublicKeys.includes(pack.publicKey)) return false;
  try {
    const alg = pack.sigAlg;
    if (alg !== undefined && alg !== 'Ed25519' && alg !== 'ECDSA-P256') return false;
    const finalAlg = alg ?? 'Ed25519';
    if (finalAlg === 'ECDSA-P256') {
      const key = await subtle().importKey('spki', bs(fromHex(pack.publicKey)), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      return await subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, key, bs(fromHex(pack.signature)), bs(utf8(pack.content_hash)));
    } else {
      const key = await subtle().importKey('spki', bs(fromHex(pack.publicKey)), { name: 'Ed25519' }, false, ['verify']);
      return await subtle().verify({ name: 'Ed25519' }, key, bs(fromHex(pack.signature)), bs(utf8(pack.content_hash)));
    }
  } catch {
    return false;
  }
}

// Helper generico para cualquier entity (no solo vehicle)
export function packMetadataForEntity(entity: string, id: string, appId: string, instanceId: string): SealedPackMetadata {
  return { entity, entityId: id, appId, instanceId, timestamp: Date.now() };
}

/**
 * @deprecated Eliminado: la version anterior fabricaba un `walletAddress` falso (0x + prefijo de la
 * publicKey) y emitia eventos con el. El anclaje real en Polygon aun no esta implementado.
 */
export function registerOnPolygon(_pack: SealedPack, _bus?: unknown): never {
  throw new Error('registerOnPolygon: not implemented');
}

export async function migratePackV2ToV3(
  pack: SealedPack,
  shares: DEKShare[],
  keyPairOrSigner?: SealedPackKeyPair | { alg: 'Ed25519' | 'ECDSA-P256'; publicKey: Uint8Array; sign(data: Uint8Array): Promise<Uint8Array> },
  pinnedPublicKeys?: string[]
): Promise<SealedPack> {
  if (!keyPairOrSigner) throw new Error('migratePackV2ToV3 requires a fresh keyPair or signer');
  if (!pinnedPublicKeys || pinnedPublicKeys.length === 0) throw new Error('migratePackV2ToV3 requires pinnedPublicKeys');
  if ((pack.v ?? 2) !== 2) throw new Error('migratePackV2ToV3 solo acepta packs v2');
  if (!(await verifySealedPackHash(pack))) throw new Error('Pack hash invalido');
  if (!(await verifySealedPackSignature(pack, pinnedPublicKeys))) throw new Error('Pack signature invalida');
  const payload = await unpackSealedPack(pack, shares);
  const metadata = { ...pack.metadata };

  let keyPair: SealedPackKeyPair | undefined;
  let signer: { alg: 'Ed25519' | 'ECDSA-P256'; publicKey: Uint8Array; sign(data: Uint8Array): Promise<Uint8Array> } | undefined;

  if ('alg' in keyPairOrSigner) {
    signer = keyPairOrSigner;
  } else {
    keyPair = keyPairOrSigner;
  }

  const migrated = await createSealedPack(payload, metadata, keyPair, {
    extraClearKeys: Object.keys(metadata).filter((k) => !CLEAR_METADATA_KEYS.includes(k)),
    signer,
  });
  migrated.id = pack.id;
  return migrated;
}
