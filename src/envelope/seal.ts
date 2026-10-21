import { b64uEncode } from './b64.js';
import { jcs } from './jcs.js';
import {
  PW_ITER_MAX, PW_ITER_MIN, PW_ITER_WRITE, PW_MIN_CHARS, aesGcmEncrypt, codeKek, grpKek, grpKid, pbkdf2Kek, randomBytes, sha256,
} from './kdf.js';
import { EnvelopeError, type Envelope, type Recipient, type SealOptions } from './types.js';
import { ENVELOPE_FMT } from './version.js';

export const MAX_FILE_BYTES = 16 * 1024 * 1024;
export const MAX_RCPT = 8;
const enc = new TextEncoder();

/** AAD for the CEK wrap of recipient type `t`. */
export function wrapAad(t: string, h: { app: string; ns: string; schema: string; created: string; seq?: number }): Uint8Array {
  return enc.encode(`swal-env/1|wrap|${t}|` + jcs({ fmt: ENVELOPE_FMT, app: h.app, ns: h.ns, schema: h.schema, created: h.created, seq: h.seq }));
}

/** Header = envelope minus ct and sig (the payload AAD, and the signed header). */
export function headerOf(e: Envelope): Omit<Envelope, 'ct' | 'sig'> {
  const { ct: _ct, sig: _sig, ...h } = e;
  return h;
}

export function signingInput(header: unknown, ctBytes: Uint8Array): Promise<Uint8Array> {
  return sha256(ctBytes).then((d) => {
    const p = enc.encode('swal-env/1|sig|' + jcs(header));
    const out = new Uint8Array(p.length + d.length);
    out.set(p); out.set(d, p.length);
    return out;
  });
}

export async function gzip(data: Uint8Array): Promise<Uint8Array> {
  const s = new Blob([data as unknown as BlobPart]).stream().pipeThrough(new CompressionStream('gzip'));
  return new Uint8Array(await new Response(s).arrayBuffer());
}

/**
 * INTERNAL (not exported from index.ts): deterministic parameters for test vectors only.
 * Reusing a CEK/IV/salt in production breaks AES-GCM; never expose this publicly.
 */
export interface FixedSealParams {
  cek?: Uint8Array;
  iv?: Uint8Array;
  /** Per-recipient salt/iv overrides, positionally matching `o.recipients`. */
  recipients?: Array<{ salt?: Uint8Array; iv?: Uint8Array }>;
  /** Raw recipient entries prepended (to test forward-compat parsing). */
  extraRcpt?: Recipient[];
}

export function sealEnvelope(o: SealOptions): Promise<Envelope> {
  return sealCore(o);
}

/** INTERNAL: test/vector generation only. */
export function sealWithFixedParams(o: SealOptions, fx: FixedSealParams): Promise<Envelope> {
  return sealCore(o, fx);
}

async function sealCore(o: SealOptions, fx: FixedSealParams = {}): Promise<Envelope> {
  if (!/^[a-z0-9-]{2,32}$/.test(o.app)) throw new EnvelopeError('format', 'bad app');
  if (typeof o.ns !== 'string' || !o.ns) throw new EnvelopeError('format', 'bad ns');
  if (!/^[a-z0-9-]+@\d+$/.test(o.schema)) throw new EnvelopeError('format', 'bad schema');
  if (o.seq !== undefined && !(Number.isSafeInteger(o.seq) && o.seq >= 0)) throw new EnvelopeError('format', 'bad seq');
  const total = o.recipients.length + (o.kem ? 1 : 0);
  if (total < 1 || total > MAX_RCPT) throw new EnvelopeError('format', 'rcpt must have 1..8 entries');

  const created = o.created ?? new Date().toISOString();
  const cek = fx.cek ?? randomBytes(32);
  const iv = fx.iv ?? randomBytes(12);
  if (cek.length !== 32 || iv.length !== 12) throw new EnvelopeError('format', 'bad cek/iv length');
  const h = { app: o.app, ns: o.ns, schema: o.schema, created, seq: o.seq };

  const rcpt: Recipient[] = [...(fx.extraRcpt ?? [])];
  for (const [idx, r] of o.recipients.entries()) {
    const salt = fx.recipients?.[idx]?.salt ?? randomBytes(16);
    const riv = fx.recipients?.[idx]?.iv ?? randomBytes(12);
    const aad = wrapAad(r.t, h);
    if (r.t === 'pw') {
      if ([...r.passphrase.normalize('NFKC')].length < PW_MIN_CHARS) throw new EnvelopeError('key', 'passphrase must be >= 12 characters');
      const i = r.iterations ?? PW_ITER_WRITE;
      if (!Number.isInteger(i) || i < PW_ITER_MIN || i > PW_ITER_MAX) throw new EnvelopeError('format', 'iterations out of bounds');
      const wk = await aesGcmEncrypt(await pbkdf2Kek(r.passphrase, salt, i), riv, cek, aad);
      rcpt.push({ t: 'pw', kdf: 'PBKDF2-SHA256', i, salt: b64uEncode(salt), iv: b64uEncode(riv), wk: b64uEncode(wk) });
    } else if (r.t === 'code') {
      const wk = await aesGcmEncrypt(await codeKek(r.secret, salt), riv, cek, aad);
      rcpt.push({ t: 'code', salt: b64uEncode(salt), iv: b64uEncode(riv), wk: b64uEncode(wk) });
    } else if (r.t === 'grp') {
      if (!Number.isSafeInteger(r.epoch) || r.epoch < 0) throw new EnvelopeError('format', 'bad epoch');
      const wk = await aesGcmEncrypt(await grpKek(r.groupKey, salt, o.ns, r.epoch), riv, cek, aad);
      rcpt.push({ t: 'grp', kid: b64uEncode(await grpKid(r.groupKey)), epoch: r.epoch, salt: b64uEncode(salt), iv: b64uEncode(riv), wk: b64uEncode(wk) });
    } else {
      throw new EnvelopeError('unsupported', 'unknown recipient spec');
    }
  }
  if (o.kem) rcpt.push(...(await o.kem.wrap({ cek, wrapAad: wrapAad('kem', h), ns: o.ns })));
  if (rcpt.length < 1 || rcpt.length > MAX_RCPT) throw new EnvelopeError('format', 'rcpt must have 1..8 entries');

  const header: Omit<Envelope, 'ct' | 'sig'> = {
    fmt: ENVELOPE_FMT, app: o.app, ns: o.ns, schema: o.schema, created,
    ...(o.seq !== undefined ? { seq: o.seq } : {}),
    ...(o.crit ? { crit: o.crit } : {}),
    aead: 'A256GCM', iv: b64uEncode(iv),
    ...(o.compress ? { z: o.compress } : {}),
    rcpt,
  };
  const body = o.compress === 'gzip' ? await gzip(o.payload) : o.payload;
  const ct = await aesGcmEncrypt(cek, iv, body, enc.encode(jcs(header)));
  const env = { ...header, ct: b64uEncode(ct) } as Envelope;
  if (o.signer) env.sig = await o.signer.sign(await signingInput(header, ct));
  if (serializeEnvelope(env).length > MAX_FILE_BYTES) throw new EnvelopeError('too-large');
  return env;
}

export function serializeEnvelope(e: Envelope): string {
  return JSON.stringify(e);
}

/** Idempotency id: b64u(SHA-256(JCS(header) || '|' || ct)). Never stored in the envelope. */
export async function computeEid(e: Envelope): Promise<string> {
  return b64uEncode(await sha256(enc.encode(jcs(headerOf(e)) + '|' + e.ct)));
}
