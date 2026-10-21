import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  ENVELOPE_VERSION, EnvelopeError, SCHEMA_IDS, b64uDecode, b64uEncode, codeAuth, codeBoxId, computeEid,
  jcs, openEnvelope, sealEnvelope, serializeEnvelope,
  type Envelope, type KemRecipientProvider, type OpenOptions, type SignatureProvider, type SealOptions,
} from '../src/envelope/index.js';
import * as envelopeApi from '../src/envelope/index.js';
import { sealWithFixedParams } from '../src/envelope/seal.js';

const V = JSON.parse(readFileSync(new URL('./vectors/swal-env-1.json', import.meta.url), 'utf8'));
const hex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const enc = new TextEncoder();
const dec = new TextDecoder();
const bs = (u: Uint8Array) => u as unknown as BufferSource;

function creds(c: any): OpenOptions {
  const o: OpenOptions = {};
  if (c.passphrase !== undefined) o.passphrase = c.passphrase;
  if (c.codeHex) o.code = hex(c.codeHex);
  if (c.groupKeyHex) o.groupKeys = [hex(c.groupKeyHex)];
  return o;
}
async function codeOf(e: unknown) {
  try { await e; } catch (x) { return x instanceof EnvelopeError ? x.code : `other:${String(x)}`; }
  return 'none';
}

describe('primitives', () => {
  it('version + registry', () => {
    expect(ENVELOPE_VERSION).toBe('1.0.0');
    expect(SCHEMA_IDS).toEqual(['swal-inventory-export@1', 'gara-g-local-dump@1', 'swal-backup@1', 'health-export@1', 'yjs-update@1']);
  });
  it('b64u strict, no padding', () => {
    expect(b64uEncode(new Uint8Array([251, 255, 254]))).toBe('-__-');
    expect(Array.from(b64uDecode('-__-'))).toEqual([251, 255, 254]);
    expect(() => b64uDecode('AA==')).toThrow(EnvelopeError);
    expect(() => b64uDecode('A')).toThrow(EnvelopeError);
  });
  it('jcs RFC 8785 ordering', () => {
    expect(jcs({ b: 1, a: [true, null, 'é'], c: undefined, 'ä': { z: 1.5, y: 1e21 } })).toBe('{"a":[true,null,"é"],"b":1,"ä":{"y":1e+21,"z":1.5}}');
  });
});

describe('vectors: positive', () => {
  for (const p of V.positive) {
    it(p.name, async () => {
      const r = await openEnvelope(JSON.stringify(p.envelope), creds(p.credentials));
      expect(dec.decode(r.payload)).toBe(V.inputs.payload);
      expect(r.header.schema).toBe(V.inputs.schema);
      if (!p.gzip) {
        const again = await sealWithFixedParams(...sealOpts(p));
        expect(again).toEqual(p.envelope);
      }
    });
  }
});

function sealOpts(p: any): [SealOptions, Parameters<typeof sealWithFixedParams>[1]] {
  const i = V.inputs;
  const recipients = p.recipients.map((r: any) => {
    if (r.t === 'pw') return { t: 'pw', passphrase: i.passphrase };
    if (r.t === 'code') return { t: 'code', secret: hex(i.codeHex) };
    return { t: 'grp', groupKey: hex(i.groupKeyHex), epoch: r.epoch };
  });
  return [{
    app: i.app, ns: i.ns, schema: i.schema, created: i.created, payload: enc.encode(i.payload),
    recipients, compress: p.gzip ? 'gzip' : undefined,
  }, {
    cek: hex(V.fixed.cekHex), iv: hex(V.fixed.ivHex),
    recipients: p.recipients.map((r: any) => ({ salt: hex(r.saltHex), iv: hex(r.ivHex) })),
  }];
}

describe('vectors: negative', () => {
  for (const n of V.negative) {
    it(`${n.name} -> ${n.expect}`, async () => {
      let input: string | Uint8Array = n.input;
      if (n.gen === 'oversize') input = new Uint8Array(16 * 1024 * 1024 + 1);
      expect(await codeOf(openEnvelope(input, creds(n.credentials)))).toBe(n.expect);
    });
  }
});

describe('behaviour', () => {
  const base = { app: 'shelf', ns: 'app/shelf/x', schema: 'yjs-update@1', payload: enc.encode('hola') };
  const gk = new Uint8Array(32).fill(7);

  it('random seal/open roundtrip with multiple recipients, any one opens', async () => {
    const secret = new Uint8Array(16).fill(3);
    const env = await sealEnvelope({
      ...base, seq: 4,
      recipients: [{ t: 'code', secret }, { t: 'grp', groupKey: gk, epoch: 2 }],
    });
    expect(env.rcpt).toHaveLength(2);
    expect(dec.decode((await openEnvelope(serializeEnvelope(env), { code: secret })).payload)).toBe('hola');
    const r = await openEnvelope(serializeEnvelope(env), { groupKeys: [new Uint8Array(32), gk] });
    expect(r.header.seq).toBe(4);
  });
  it('rejects short passphrase on write, bad count, unknown t ignored on read', async () => {
    expect(await codeOf(sealEnvelope({ ...base, recipients: [{ t: 'pw', passphrase: 'short' }] }))).toBe('key');
    expect(await codeOf(sealEnvelope({ ...base, recipients: [] }))).toBe('format');
    const rc = Array.from({ length: 9 }, () => ({ t: 'grp' as const, groupKey: gk, epoch: 1 }));
    expect(await codeOf(sealEnvelope({ ...base, recipients: rc }))).toBe('format');
    const env: any = await sealEnvelope({ ...base, recipients: [{ t: 'grp', groupKey: gk, epoch: 1 }] });
    env.rcpt.unshift({ t: 'future', x: 1 });
    // header changed => payload AAD differs => tampered, but the unknown recipient itself is skipped (not format/unsupported)
    expect(await codeOf(openEnvelope(JSON.stringify(env), { groupKeys: [gk] }))).toBe('tampered');
  });
  it('code helpers are deterministic', async () => {
    const s = new Uint8Array(16).fill(1);
    expect(await codeBoxId(s)).toMatch(/^[0-9a-f]{32}$/);
    expect((await codeAuth(s)).length).toBe(32);
  });
  it('eid is stable and header-sensitive', async () => {
    const env = await sealEnvelope({ ...base, recipients: [{ t: 'grp', groupKey: gk, epoch: 1 }] });
    const a = await computeEid(env);
    expect(a).toBe(await computeEid(JSON.parse(serializeEnvelope(env))));
    expect(a).not.toBe(await computeEid({ ...env, ns: 'other' }));
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect('eid' in env).toBe(false);
  });
  it('gzip round-trips and shrinks', async () => {
    const big = enc.encode('abc'.repeat(5000));
    const env = await sealEnvelope({ ...base, payload: big, compress: 'gzip', recipients: [{ t: 'grp', groupKey: gk, epoch: 1 }] });
    expect(env.z).toBe('gzip');
    expect(b64uDecode(env.ct).length).toBeLessThan(big.length / 4);
    expect((await openEnvelope(serializeEnvelope(env), { groupKeys: [gk] })).payload).toEqual(big);
  });
  it('replay: seq <= high-water', async () => {
    const env = await sealEnvelope({ ...base, seq: 5, recipients: [{ t: 'grp', groupKey: gk, epoch: 1 }] });
    expect(await codeOf(openEnvelope(serializeEnvelope(env), { groupKeys: [gk], seqHighWater: 5 }))).toBe('replay');
    await openEnvelope(serializeEnvelope(env), { groupKeys: [gk], seqHighWater: 4 });
  });

  it('kem + signature provider hooks', async () => {
    const kekRaw = new Uint8Array(32).fill(9);
    const key = await crypto.subtle.importKey('raw', bs(kekRaw), 'AES-GCM', false, ['encrypt', 'decrypt']);
    const kem: KemRecipientProvider = {
      t: 'kem',
      async wrap({ cek, wrapAad }) {
        const iv = new Uint8Array(12).fill(5);
        const wk = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: bs(iv), additionalData: bs(wrapAad) }, key, bs(cek)));
        return [{ t: 'kem', kid: 'dev1', iv: b64uEncode(iv), wk: b64uEncode(wk) }];
      },
      async unwrap(r, { wrapAad }) {
        try {
          return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bs(b64uDecode(r.iv as string)), additionalData: bs(wrapAad) }, key, bs(b64uDecode(r.wk as string))));
        } catch { return null; }
      },
    };
    const hmacKey = await crypto.subtle.importKey('raw', bs(kekRaw), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    const signer: SignatureProvider = {
      async sign(input) { return { alg: 'HMAC-TEST', kid: 'k', v: b64uEncode(new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, bs(input)))) }; },
      async verify(sig, input) { return crypto.subtle.verify('HMAC', hmacKey, bs(b64uDecode(sig.v as string)), bs(input)); },
    };
    const env = await sealEnvelope({ ...base, seq: 1, recipients: [], kem, signer });
    expect(env.rcpt[0].t).toBe('kem');
    expect(env.sig?.alg).toBe('HMAC-TEST');
    const r = await openEnvelope(serializeEnvelope(env), { kem, verifier: signer, requireSignature: true });
    expect(r.signatureVerified).toBe(true);
    const bad: Envelope = { ...env, sig: { ...env.sig!, v: b64uEncode(new Uint8Array(32)) } };
    expect(await codeOf(openEnvelope(serializeEnvelope(bad), { kem, verifier: signer }))).toBe('signature');
    const unsigned = { ...env } as any; delete unsigned.sig;
    expect(await codeOf(openEnvelope(JSON.stringify(unsigned), { kem, verifier: signer, requireSignature: true }))).toBe('signature');
    // ct swap after signing is detected by the signature before decryption
    const t2 = { ...env, ct: (await sealEnvelope({ ...base, recipients: [{ t: 'grp', groupKey: gk, epoch: 1 }] })).ct };
    expect(await codeOf(openEnvelope(JSON.stringify(t2), { kem, verifier: signer }))).toBe('signature');
  });

  it('two identical seals differ in iv, ct, salt, wrap iv and wk (pw, code, grp)', async () => {
    const opts = {
      ...base,
      recipients: [
        { t: 'pw' as const, passphrase: 'correct horse battery' },
        { t: 'code' as const, secret: new Uint8Array(16).fill(3) },
        { t: 'grp' as const, groupKey: gk, epoch: 1 },
      ],
    };
    const a: any = await sealEnvelope(opts);
    const b: any = await sealEnvelope(opts);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ct).not.toBe(b.ct);
    for (let i = 0; i < 3; i++) {
      expect(a.rcpt[i].salt).not.toBe(b.rcpt[i].salt);
      expect(a.rcpt[i].iv).not.toBe(b.rcpt[i].iv);
      expect(a.rcpt[i].wk).not.toBe(b.rcpt[i].wk); // random CEK => different wrapped key
    }
  });
  it('requireSignature + sig present but no verifier -> signature', async () => {
    const signer: SignatureProvider = {
      async sign() { return { alg: 'X', kid: 'k', v: 'AAAA' }; },
      async verify() { return true; },
    };
    const env = await sealEnvelope({ ...base, recipients: [{ t: 'grp', groupKey: gk, epoch: 1 }], signer });
    expect(env.sig).toBeDefined();
    expect(await codeOf(openEnvelope(serializeEnvelope(env), { groupKeys: [gk], requireSignature: true }))).toBe('signature');
    expect((await openEnvelope(serializeEnvelope(env), { groupKeys: [gk] })).signatureVerified).toBe(false);
  });
  it('fixed/salt/iv test params are not public API', async () => {
    expect(Object.keys(envelopeApi)).not.toContain('sealWithFixedParams');
    const fixedOpts: any = { cek: new Uint8Array(32), iv: new Uint8Array(12) };
    const rec: any = { t: 'grp', groupKey: gk, epoch: 1, salt: new Uint8Array(16), iv: new Uint8Array(12) };
    // @ts-expect-error `fixed` is not part of SealOptions
    const a = await sealEnvelope({ ...base, recipients: [rec], fixed: fixedOpts });
    const b = await sealEnvelope({ ...base, recipients: [rec], fixed: fixedOpts } as SealOptions);
    expect(a.iv).not.toBe(b.iv);
    expect(a.iv).not.toBe(b64uEncode(new Uint8Array(12)));
    expect((a.rcpt[0] as any).salt).not.toBe((b.rcpt[0] as any).salt);
    expect((a.rcpt[0] as any).salt).not.toBe(b64uEncode(new Uint8Array(16)));
  });
  it('unknown pw kdf on one recipient is skipped when another recipient opens', async () => {
    const withFuture = await sealWithFixedParams(
      { ...base, recipients: [{ t: 'grp', groupKey: gk, epoch: 1 }], created: '2026-01-01T00:00:00.000Z' },
      { cek: new Uint8Array(32).fill(1), iv: new Uint8Array(12).fill(2), extraRcpt: [{ t: 'pw', kdf: 'argon2id', i: 3, salt: 'x', iv: 'y', wk: 'z' }] },
    );
    expect(withFuture.rcpt[0].t).toBe('pw');
    const r = await openEnvelope(serializeEnvelope(withFuture), { groupKeys: [gk], passphrase: 'correct horse battery' });
    expect(dec.decode(r.payload)).toBe('hola');
    expect(r.via).toBe('grp');
    expect(await codeOf(openEnvelope(serializeEnvelope(withFuture), { passphrase: 'correct horse battery' }))).toBe('unsupported');
  });
});
