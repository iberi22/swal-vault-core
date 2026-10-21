import { b64uDecode } from './b64.js';
import { jcs } from './jcs.js';
import {
  PW_ITER_MAX, PW_ITER_MIN, aesGcmDecrypt, codeKek, grpKek, grpKid, pbkdf2Kek,
} from './kdf.js';
import { MAX_FILE_BYTES, MAX_RCPT, headerOf, signingInput, wrapAad } from './seal.js';
import { EnvelopeError, type Envelope, type OpenOptions, type OpenResult, type OtherRecipient } from './types.js';
import { ENVELOPE_FMT } from './version.js';

const enc = new TextEncoder();
const KNOWN_CRIT = new Set<string>();
const MAX_INFLATED = 4 * MAX_FILE_BYTES;

function isObj(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}
function fixed(s: unknown, n: number, what: string): Uint8Array {
  const b = b64uDecode(s);
  if (b.length !== n) throw new EnvelopeError('format', `${what} must be ${n} bytes`);
  return b;
}

export async function gunzip(data: Uint8Array): Promise<Uint8Array> {
  const s = new Blob([data as unknown as BlobPart]).stream().pipeThrough(new DecompressionStream('gzip'));
  const reader = s.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > MAX_INFLATED) { await reader.cancel(); throw new EnvelopeError('too-large', 'inflated payload'); }
    chunks.push(value);
  }
  const out = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

function parse(input: string | Uint8Array | Envelope): Envelope {
  let v: unknown = input;
  if (typeof input === 'string' || input instanceof Uint8Array) {
    // size check BEFORE JSON.parse (string length is a lower bound of the UTF-8 size)
    if (input.length > MAX_FILE_BYTES) throw new EnvelopeError('too-large');
    const text = typeof input === 'string' ? input : new TextDecoder().decode(input);
    if (enc.encode(text).length > MAX_FILE_BYTES) throw new EnvelopeError('too-large');
    try { v = JSON.parse(text); } catch { throw new EnvelopeError('format', 'invalid JSON'); }
  }
  if (!isObj(v)) throw new EnvelopeError('format', 'not an object');
  return v as Envelope;
}

function validate(e: Envelope): void {
  if (typeof e.fmt !== 'string') throw new EnvelopeError('format', 'missing fmt');
  if (e.fmt !== ENVELOPE_FMT) throw new EnvelopeError('unsupported', 'fmt');
  if (typeof e.app !== 'string' || !/^[a-z0-9-]{2,32}$/.test(e.app)) throw new EnvelopeError('format', 'app');
  if (typeof e.ns !== 'string' || !e.ns) throw new EnvelopeError('format', 'ns');
  if (typeof e.schema !== 'string' || !/^[a-z0-9-]+@\d+$/.test(e.schema)) throw new EnvelopeError('format', 'schema');
  if (typeof e.created !== 'string') throw new EnvelopeError('format', 'created');
  if (e.seq !== undefined && !(Number.isSafeInteger(e.seq) && e.seq >= 0)) throw new EnvelopeError('format', 'seq');
  if (e.crit !== undefined) {
    if (!Array.isArray(e.crit) || e.crit.some((c) => typeof c !== 'string')) throw new EnvelopeError('format', 'crit');
    if (e.crit.some((c) => !KNOWN_CRIT.has(c))) throw new EnvelopeError('unsupported', 'unknown crit entry');
  }
  if (e.aead !== 'A256GCM') throw new EnvelopeError('unsupported', 'aead');
  fixed(e.iv, 12, 'iv');
  if (e.z !== undefined && e.z !== 'gzip') throw new EnvelopeError('unsupported', 'z');
  if (typeof e.ct !== 'string') throw new EnvelopeError('format', 'ct');
  if (!Array.isArray(e.rcpt) || e.rcpt.length < 1 || e.rcpt.length > MAX_RCPT) throw new EnvelopeError('format', 'rcpt count');
  for (const r of e.rcpt) {
    if (!isObj(r) || typeof r.t !== 'string') throw new EnvelopeError('format', 'rcpt entry');
    if (r.t === 'pw') {
      if (r.kdf !== 'PBKDF2-SHA256') continue; // unknown kdf (e.g. reserved argon2id): skipped; see tryUnwrap
      if (!Number.isInteger(r.i) || (r.i as number) < PW_ITER_MIN || (r.i as number) > PW_ITER_MAX) throw new EnvelopeError('format', 'i out of bounds');
    }
    if (r.t === 'pw' || r.t === 'code' || r.t === 'grp') {
      fixed(r.salt, 16, 'salt'); fixed(r.iv, 12, 'rcpt iv'); fixed(r.wk, 48, 'wk');
    }
    if (r.t === 'grp') {
      fixed(r.kid, 16, 'kid');
      if (!Number.isSafeInteger(r.epoch) || (r.epoch as number) < 0) throw new EnvelopeError('format', 'epoch');
    }
  }
  if (e.sig !== undefined && (!isObj(e.sig) || typeof e.sig.alg !== 'string' || typeof e.sig.kid !== 'string' || typeof e.sig.v !== 'string')) {
    throw new EnvelopeError('format', 'sig');
  }
}

async function tryUnwrap(e: Envelope, o: OpenOptions): Promise<{ cek: Uint8Array; via: string } | null> {
  const ns = e.ns;
  for (const r of e.rcpt as OtherRecipient[]) {
    try {
      const aad = wrapAad(r.t, e);
      const dw = async (kek: Uint8Array) =>
        aesGcmDecrypt(kek, b64uDecode(r.iv), b64uDecode(r.wk), aad);
      if (r.t === 'pw' && r.kdf !== 'PBKDF2-SHA256') continue;
      if (r.t === 'pw' && o.passphrase !== undefined) {
        return { cek: await dw(await pbkdf2Kek(o.passphrase, b64uDecode(r.salt), r.i as number)), via: 'pw' };
      }
      if (r.t === 'code' && o.code) {
        return { cek: await dw(await codeKek(o.code, b64uDecode(r.salt))), via: 'code' };
      }
      if (r.t === 'grp' && o.groupKeys) {
        for (const gk of o.groupKeys) {
          if (b64uDecodeEq(await grpKid(gk), r.kid as string)) {
            return { cek: await dw(await grpKek(gk, b64uDecode(r.salt), ns, r.epoch as number)), via: 'grp' };
          }
        }
      }
      if (r.t === 'kem' && o.kem) {
        const cek = await o.kem.unwrap(r, { wrapAad: aad, ns });
        if (cek && cek.length === 32) return { cek, via: 'kem' };
      }
    } catch { /* this recipient did not open; unknown t are simply skipped */ }
  }
  return null;
}
function b64uDecodeEq(a: Uint8Array, b: string): boolean {
  const x = b64uDecode(b);
  if (x.length !== a.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ x[i];
  return d === 0;
}

export async function openEnvelope(input: string | Uint8Array | Envelope, o: OpenOptions = {}): Promise<OpenResult> {
  const e = parse(input);
  validate(e);
  const ct = b64uDecode(e.ct);
  const header = headerOf(e);

  if (e.seq !== undefined && o.seqHighWater !== undefined && e.seq <= o.seqHighWater) throw new EnvelopeError('replay');

  let signatureVerified = false;
  if (e.sig) {
    if (o.verifier) {
      let ok = false;
      try { ok = await o.verifier.verify(e.sig, await signingInput(header, ct)); } catch { ok = false; }
      if (!ok) throw new EnvelopeError('signature');
      signatureVerified = true;
    } else if (o.requireSignature) throw new EnvelopeError('signature', 'no verifier');
  } else if (o.requireSignature) throw new EnvelopeError('signature', 'unsigned');

  const u = await tryUnwrap(e, o);
  if (!u && e.rcpt.some((r) => r.t === 'pw' && r.kdf !== 'PBKDF2-SHA256')) throw new EnvelopeError('unsupported', 'kdf');
  if (!u) throw new EnvelopeError('key', 'no recipient could be opened');

  if (ct.length < 16) throw new EnvelopeError('tampered', 'truncated');
  let body: Uint8Array;
  try {
    body = await aesGcmDecrypt(u.cek, b64uDecode(e.iv), ct, enc.encode(jcs(header)));
  } catch { throw new EnvelopeError('tampered'); }
  if (e.z === 'gzip') {
    try { body = await gunzip(body); } catch (x) {
      if (x instanceof EnvelopeError) throw x;
      throw new EnvelopeError('format', 'bad gzip');
    }
  }
  return { payload: body, header, via: u.via, signed: !!e.sig, signatureVerified };
}
