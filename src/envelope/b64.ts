import { EnvelopeError } from './types.js';

const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const REV = new Int8Array(128).fill(-1);
for (let i = 0; i < 64; i++) REV[A.charCodeAt(i)] = i;

/** base64url, no padding. */
export function b64uEncode(b: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    out += A[n >> 18] + A[(n >> 12) & 63] + A[(n >> 6) & 63] + A[n & 63];
  }
  const r = b.length - i;
  if (r === 1) {
    const n = b[i] << 16;
    out += A[n >> 18] + A[(n >> 12) & 63];
  } else if (r === 2) {
    const n = (b[i] << 16) | (b[i + 1] << 8);
    out += A[n >> 18] + A[(n >> 12) & 63] + A[(n >> 6) & 63];
  }
  return out;
}

/** Strict decode: rejects padding, foreign chars, impossible lengths, non-canonical trailing bits. */
export function b64uDecode(s: unknown): Uint8Array {
  if (typeof s !== 'string') throw new EnvelopeError('format', 'base64url expected');
  const len = s.length;
  if (len % 4 === 1) throw new EnvelopeError('format', 'bad base64url length');
  const vals = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? REV[c] : -1;
    if (v < 0) throw new EnvelopeError('format', 'bad base64url char');
    vals[i] = v;
  }
  const out = new Uint8Array(Math.floor((len * 3) / 4));
  let o = 0;
  let i = 0;
  for (; i + 3 < len; i += 4) {
    const n = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6) | vals[i + 3];
    out[o++] = n >> 16; out[o++] = (n >> 8) & 255; out[o++] = n & 255;
  }
  const r = len - i;
  if (r === 2) {
    if (vals[i + 1] & 15) throw new EnvelopeError('format', 'non-canonical base64url');
    out[o++] = (vals[i] << 2) | (vals[i + 1] >> 4);
  } else if (r === 3) {
    if (vals[i + 2] & 3) throw new EnvelopeError('format', 'non-canonical base64url');
    out[o++] = (vals[i] << 2) | (vals[i + 1] >> 4);
    out[o++] = ((vals[i + 1] & 15) << 4) | (vals[i + 2] >> 2);
  }
  return out;
}
