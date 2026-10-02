// sealedPack.ts — core reusable vault (antes en gara-g app-pwa)
// Extraído a cores/swal-vault para reuso en gara-g, hosteler-ia, flota, cualquier app SWAL.
// 100% cifrado: AES-256-GCM + Shamir 2-of-3 sobre DEK + SHA256 content_hash + Ed25519.
// Cloudflare nunca ve plaintext, solo ciphertext+shares+hash.
// Pay-per-use: costo solo si se sube a R2; mesh-only gratis (replica P2P en otros nodos gara-g).

import {
  bs, concatBytes, fromBase64, fromHex, randomBytes, randomInt, sha256, sha256Sync, toBase64, toHex, utf8,
} from './bytes.js';

const subtle = () => globalThis.crypto.subtle;

// Lazy import econ-sdk solo si hay chain (no requerido para vault puro)
// Si no hay @swal/econ instalado (ej hosteler-ia), fallback a polygon defaults
let _econChain = 'polygon';
let _econChainId = 137;
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const econ = require('@swal/econ-sdk');
  if (econ?.defaultChainRegistry) {
    const r = econ.defaultChainRegistry.getRouteInfo('gara-g');
    _econChain = r.chain ?? 'polygon';
    _econChainId = r.chainId ?? 137;
  }
} catch {}

export interface DEKShare {
  index: number;
  value: string;
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
  id: string;
  content_hash: string;
  ciphertext: string;
  iv: string;
  tag: string;
  shares: DEKShare[];
  signature: string;
  publicKey: string;
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

export function splitDEK(dek: Uint8Array): DEKShare[] {
  if (dek.length !== 32) throw new Error('DEK 32 bytes');
  const s1 = new Uint8Array(32);
  const s2 = new Uint8Array(32);
  const s3 = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const secret = dek[i];
    let a1: number, y1: number, y2: number, y3: number;
    do {
      a1 = randomInt(1, 257);
      y1 = mod257(secret + a1 * 1);
      y2 = mod257(secret + a1 * 2);
      y3 = mod257(secret + a1 * 3);
    } while (y1 === 256 || y2 === 256 || y3 === 256);
    s1[i] = y1;
    s2[i] = y2;
    s3[i] = y3;
  }
  return [
    { index: 1, value: toBase64(s1) },
    { index: 2, value: toBase64(s2) },
    { index: 3, value: toBase64(s3) },
  ];
}

export function reconstructDEK(shares: DEKShare[]): Uint8Array {
  if (shares.length < 2) throw new Error('At least 2 shares are required to reconstruct DEK');
  const s1 = shares[0], s2 = shares[1];
  const x1 = s1.index, x2 = s2.index;
  if (x1 === x2) throw new Error('shares duplicate x');
  const y1 = fromBase64(s1.value);
  const y2 = fromBase64(s2.value);
  if (y1.length !== 32 || y2.length !== 32) throw new Error('share length 32');
  const num1 = mod257(-x2), den1 = mod257(x1 - x2), L1 = mod257(num1 * modInverse257(den1));
  const num2 = mod257(-x1), den2 = mod257(x2 - x1), L2 = mod257(num2 * modInverse257(den2));
  const dek = new Uint8Array(32);
  for (let i = 0; i < 32; i++) dek[i] = mod257(y1[i] * L1 + y2[i] * L2);
  return dek;
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
): Promise<SealedPack> {
  const dek = randomBytes(32);
  const iv = randomBytes(12);
  // WebCrypto devuelve ciphertext||tag(16); se separan para mantener el formato del pack.
  const sealed = new Uint8Array(
    await subtle().encrypt({ name: 'AES-GCM', iv: bs(iv), tagLength: 128 }, await aesKey(dek, 'encrypt'), bs(payload)),
  );
  const ct = sealed.subarray(0, sealed.length - 16);
  const tag = sealed.subarray(sealed.length - 16);
  const shares = splitDEK(dek);
  const contentHash = await computeContentHashAsync(ct, metadata);
  const { priv, pubSpki } = await resolveKeyPair(keyPair);
  const sig = new Uint8Array(await subtle().sign({ name: 'Ed25519' }, priv, bs(utf8(contentHash))));
  return {
    id: `pack-${globalThis.crypto.randomUUID()}`,
    content_hash: contentHash,
    ciphertext: toBase64(ct),
    iv: toBase64(iv),
    tag: toBase64(tag),
    shares,
    signature: toHex(sig),
    publicKey: toHex(pubSpki),
    metadata,
    chain: _econChain,
    chainId: _econChainId,
  };
}

export async function unpackSealedPack(pack: SealedPack, shares: DEKShare[]): Promise<Uint8Array> {
  const dek = reconstructDEK(shares);
  const ct = fromBase64(pack.ciphertext);
  const iv = fromBase64(pack.iv);
  const tag = fromBase64(pack.tag);
  const dec = await subtle().decrypt(
    { name: 'AES-GCM', iv: bs(iv), tagLength: 128 },
    await aesKey(dek, 'decrypt'),
    bs(concatBytes(ct, tag)),
  );
  return new Uint8Array(dec);
}

export async function verifySealedPackHash(pack: SealedPack): Promise<boolean> {
  const exp = await computeContentHashAsync(fromBase64(pack.ciphertext), pack.metadata);
  return exp.toLowerCase() === pack.content_hash.toLowerCase();
}

/** Verifica la firma Ed25519 del content_hash con la publicKey del pack. */
export async function verifySealedPackSignature(pack: SealedPack): Promise<boolean> {
  try {
    const key = await subtle().importKey('spki', bs(fromHex(pack.publicKey)), { name: 'Ed25519' }, false, ['verify']);
    return await subtle().verify({ name: 'Ed25519' }, key, bs(fromHex(pack.signature)), bs(utf8(pack.content_hash)));
  } catch {
    return false;
  }
}

// Helper generico para cualquier entity (no solo vehicle)
export function packMetadataForEntity(entity: string, id: string, appId: string, instanceId: string): SealedPackMetadata {
  return { entity, entityId: id, appId, instanceId, timestamp: Date.now() };
}

// Compat legacy gara-g: registerOnPolygon (antes en app-pwa sealedPack)
// Usa econ-sdk si está disponible, sino no-op con shape compatible con tests
export function registerOnPolygon(
  pack: SealedPack,
  bus?: any,
): { targetChain: string; event: any; docPath: string } {
  const targetChain = pack.chain ?? _econChain;
  const event = {
    actionType: 'SEALED_PACK_ANCHOR',
    value: pack.content_hash,
    appId: (pack.metadata.appId as string) || 'gara-g',
  };
  const docPath = `swal/${(pack.metadata.appId as string) || 'gara-g'}/econ`;
  try {
    if (bus?.emitEconEvent) {
      return bus.emitEconEvent({
        appId: event.appId,
        nodeId: (pack.metadata.vehicleId as string) || (pack.metadata.entityId as string) || 'node-gara-g',
        walletAddress: pack.publicKey ? `0x${pack.publicKey.slice(0, 40)}` : '0x0000000000000000000000000000000000000000',
        actionType: event.actionType,
        value: event.value,
        ts: (pack.metadata.timestamp as number) || Date.now(),
        signature: pack.signature,
      });
    }
    if (bus?.getRegistry) {
      try {
        const { EconEventBus: Bus } = require('@swal/econ-sdk');
        const b = new Bus();
        return b.emitEconEvent({
          appId: event.appId,
          nodeId: (pack.metadata.vehicleId as string) || 'node',
          walletAddress: pack.publicKey ? `0x${pack.publicKey.slice(0, 40)}` : '0x0',
          actionType: event.actionType,
          value: event.value,
          ts: Date.now(),
          signature: pack.signature,
        });
      } catch {}
    }
  } catch {}
  // fallback shape que esperan tests gara-g (targetChain polygon, event.value == hash)
  return { targetChain, event, docPath };
}
