import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { EnvelopeError, MAX_FILE_BYTES, openEnvelope, sealEnvelope, serializeEnvelope } from '../src/envelope/index.js';
import { KNOWN_CRIT, MAX_INFLATED } from '../src/envelope/limits.js';

const secret = new Uint8Array(16).fill(7);
const base = { app: 'test-app', ns: 'ns', schema: 'doc@1', recipients: [{ t: 'code' as const, secret }] };
const code = secret;

async function code_of(p: () => Promise<unknown>): Promise<string | undefined> {
  try { await p(); } catch (e) { return (e as EnvelopeError).code; }
  return undefined;
}

describe('seal limits mirror open', () => {
  it('rejects gzip payload above MAX_INFLATED at seal time', async () => {
    const payload = new Uint8Array(MAX_INFLATED + 1);
    expect(await code_of(() => sealEnvelope({ ...base, payload, compress: 'gzip' }))).toBe('too-large');
  }, 60_000);

  it('rejects unknown crit at seal time (same as open)', async () => {
    expect(KNOWN_CRIT.size).toBe(0);
    expect(await code_of(() => sealEnvelope({ ...base, payload: new Uint8Array(4), crit: ['x'] }))).toBe('unsupported');
  });

  it('measures UTF-8 bytes, not UTF-16 units, for the file limit', async () => {
    const ns = 'é'.repeat(1_000_000);
    const mk = (n: number) => ({ ...base, ns, payload: new Uint8Array(n) });
    const probe = serializeEnvelope(await sealEnvelope(mk(0)));
    const ctLen = (n: number) => Math.ceil((4 * (n + 16)) / 3);
    const overhead = probe.length - ctLen(0);
    // string length just under the limit, UTF-8 bytes over it
    const n = Math.floor(((MAX_FILE_BYTES - overhead - 100) * 3) / 4) - 16;
    const o = mk(n);
    expect(overhead + ctLen(n)).toBeLessThan(MAX_FILE_BYTES); // UTF-16 length passes the old check
    const err = await code_of(() => sealEnvelope(o));
    expect(err).toBe('too-large');
  }, 60_000);

  it('whatever seal accepts, open accepts', async () => {
    const e = await sealEnvelope({ ...base, payload: new Uint8Array(1024), compress: 'gzip' });
    expect((await openEnvelope(e, { code })).payload.length).toBe(1024);
  });
});

describe('vendor script dest guard', () => {
  it.each(['.', 'src', 'src/envelope', 'src/envelope/sub', 'test/vectors', 'test'])('refuses dest %s without deleting', (d) => {
    let status = 0;
    try { execFileSync('node', ['scripts/vendor-envelope.mjs', d], { stdio: 'pipe' }); } catch (e) { status = (e as { status: number }).status; }
    expect(status).toBe(1);
    expect(existsSync('src/envelope/seal.ts')).toBe(true);
    expect(existsSync('test/vectors')).toBe(true);
  });
});
