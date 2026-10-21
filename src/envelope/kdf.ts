import { EnvelopeError } from './types.js';

export const PW_ITER_WRITE = 600_000;
export const PW_ITER_MIN = 210_000;
export const PW_ITER_MAX = 10_000_000;
export const PW_MIN_CHARS = 12;

const enc = new TextEncoder();
const bs = (u: Uint8Array) => u as unknown as BufferSource;
const subtle = () => globalThis.crypto.subtle;

export function randomBytes(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}
export const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

export async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  let n = 0;
  for (const p of parts) n += p.length;
  const all = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { all.set(p, o); o += p.length; }
  return new Uint8Array(await subtle().digest('SHA-256', bs(all)));
}

export async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string, len: number): Promise<Uint8Array> {
  const k = await subtle().importKey('raw', bs(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await subtle().deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: bs(salt), info: bs(enc.encode(info)) }, k, len * 8);
  return new Uint8Array(bits);
}

export async function pbkdf2Kek(pass: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const k = await subtle().importKey('raw', bs(enc.encode(pass.normalize('NFKC'))), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle().deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: bs(salt), iterations }, k, 256));
}

function need(b: Uint8Array, n: number, what: string) {
  if (!(b instanceof Uint8Array) || b.length !== n) throw new EnvelopeError('key', `${what} must be ${n} bytes`);
}
const EMPTY = new Uint8Array(0);

export function codeKek(secret16: Uint8Array, salt: Uint8Array) {
  need(secret16, 16, 'code secret');
  return hkdf(secret16, salt, 'swal-env/1|code|kek', 32);
}
export async function codeBoxId(secret16: Uint8Array): Promise<string> {
  need(secret16, 16, 'code secret');
  return toHex(await hkdf(secret16, EMPTY, 'swal-env/1|code|box', 16));
}
export function codeAuth(secret16: Uint8Array): Promise<Uint8Array> {
  need(secret16, 16, 'code secret');
  return hkdf(secret16, EMPTY, 'swal-env/1|code|auth', 32);
}
export function grpKek(groupKey: Uint8Array, salt: Uint8Array, ns: string, epoch: number) {
  need(groupKey, 32, 'group key');
  return hkdf(groupKey, salt, `swal-env/1|grp|${ns}|${epoch}`, 32);
}
/** 16-byte group key id. */
export function grpKid(groupKey: Uint8Array): Promise<Uint8Array> {
  need(groupKey, 32, 'group key');
  return hkdf(groupKey, EMPTY, 'swal-env/1|grp|kid', 16);
}

export async function aesGcmEncrypt(rawKey: Uint8Array, iv: Uint8Array, data: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  const k = await subtle().importKey('raw', bs(rawKey), 'AES-GCM', false, ['encrypt']);
  return new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: bs(iv), additionalData: bs(aad) }, k, bs(data)));
}
/** Throws the raw WebCrypto error on auth failure; callers map it. */
export async function aesGcmDecrypt(rawKey: Uint8Array, iv: Uint8Array, data: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  const k = await subtle().importKey('raw', bs(rawKey), 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: bs(iv), additionalData: bs(aad) }, k, bs(data)));
}
