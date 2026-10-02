import 'fake-indexeddb/auto';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  computeContentHash, computeContentHashAsync, createSealedPack, reconstructDEK, splitDEK,
  unpackSealedPack, verifySealedPackHash, verifySealedPackSignature,
} from '../src/index.js';
import { randomBytes, sha256Sync, toHex } from '../src/bytes.js';
import { createVaultClient, VaultError } from '../src/web/vault-client.js';

const meta = { entity: 'x', timestamp: 1 };
let n = 0;
const client = (extra = {}) => createVaultClient({ storage: 'idb', dbName: `t${n++}`, ...extra });

describe('sealedPack (WebCrypto)', () => {
  it('round-trip con 2 shares cualquiera y verifica hash y firma', async () => {
    const payload = new TextEncoder().encode('hola salud');
    const pack = await createSealedPack(payload, meta);
    expect(await verifySealedPackHash(pack)).toBe(true);
    expect(await verifySealedPackSignature(pack)).toBe(true);
    for (const pair of [[0, 1], [1, 2], [0, 2]])
      expect(await unpackSealedPack(pack, pair.map((i) => pack.shares[i]))).toEqual(payload);
    pack.ciphertext = pack.ciphertext.replace(/^./, (c) => (c === 'A' ? 'B' : 'A'));
    expect(await verifySealedPackHash(pack)).toBe(false);
  });
  it('acepta par de claves de node (compat) y sha256 sync == async', async () => {
    const pack = await createSealedPack(new Uint8Array([1, 2, 3]), meta, generateKeyPairSync('ed25519'));
    expect(await verifySealedPackSignature(pack)).toBe(true);
    const ct = randomBytes(1000);
    expect(computeContentHash(ct, meta)).toBe(await computeContentHashAsync(ct, meta));
    for (const len of [0, 1, 55, 56, 64, 119, 5000]) {
      const b = randomBytes(len);
      expect(toHex(sha256Sync(b))).toBe(createHash('sha256').update(b).digest('hex'));
    }
  });
  it('Shamir 2-de-3', () => {
    const dek = randomBytes(32);
    const s = splitDEK(dek);
    for (const [a, b] of [[0, 1], [0, 2], [1, 2], [2, 0]]) expect(reconstructDEK([s[a], s[b]])).toEqual(dek);
    expect(() => reconstructDEK([s[0]])).toThrow();
    expect(reconstructDEK([s[0], s[1]])).not.toEqual(randomBytes(32));
  });
});

describe('VaultClient', () => {
  it('identidad de dispositivo persiste y firma/verifica', async () => {
    const c = client();
    const id = await c.getDeviceIdentity();
    expect((await c.getDeviceIdentity()).deviceId).toBe(id.deviceId);
    const data = new Uint8Array([9, 9]);
    const sig = await c.sign(data);
    expect(await c.verify(id.publicKeyJwk, data, sig)).toBe(true);
    expect(await c.verify(id.publicKeyJwk, new Uint8Array([1]), sig)).toBe(false);
  });
  it('wrap/unwrap y passphrase incorrecta falla', async () => {
    const c = client({ pbkdf2Iterations: 310_000 });
    expect(c.isUnlocked()).toBe(false);
    await expect(c.getOrCreateMeshKey()).rejects.toMatchObject({ code: 'LOCKED' });
    await c.unlock({ passphrase: 'correcta' });
    const raw = randomBytes(32);
    expect(await c.unwrapKey(await c.wrapKey(raw))).toEqual(raw);
    const mk = await c.getOrCreateMeshKey();
    expect((await c.getOrCreateMeshKey()).raw).toEqual(mk.raw);
    c.lock();
    await expect(c.unlock({ passphrase: 'mala' })).rejects.toBeInstanceOf(VaultError);
    expect(c.isUnlocked()).toBe(false);
    await c.unlock({ passphrase: 'correcta' });
    expect((await c.getOrCreateMeshKey()).raw).toEqual(mk.raw);
  });
  it('rechaza iteraciones < 310k', () => {
    expect(() => client({ pbkdf2Iterations: 1000 })).toThrow(VaultError);
  });
  it('passkey PRF inyectado y fallback a passphrase', async () => {
    const prf = { getPrfOutput: async (salt: Uint8Array) => salt.length ? new Uint8Array(32).fill(7) : new Uint8Array() };
    const c = client({ passkey: prf });
    expect(c.isPasskeyPrfAvailable()).toBe(true);
    expect(await c.unlockPreferPasskey('x')).toBe('passkey');
    const mk = await c.getOrCreateMeshKey();
    c.lock();
    await c.unlock({ passkey: true });
    expect((await c.getOrCreateMeshKey()).raw).toEqual(mk.raw);
    const bad = { getPrfOutput: async () => { throw new VaultError('NO_PASSKEY', 'no'); } };
    expect(await client({ passkey: bad }).unlockPreferPasskey('pw')).toBe('passphrase');
  });
  it('share de recuperacion: una sola vez, recupera y resetea passphrase', async () => {
    const c = client();
    await c.unlock({ passphrase: 'a' });
    const mk = await c.getOrCreateMeshKey();
    const { recoveryShare } = await c.exportRecoveryShare();
    await expect(c.exportRecoveryShare()).rejects.toMatchObject({ code: 'SHARE_ALREADY_SHOWN' });
    expect(await c.recoverMeshKey(recoveryShare)).toEqual(mk.raw);
    await c.resetPassphrase(recoveryShare, 'nueva');
    c.lock();
    await expect(c.unlock({ passphrase: 'a' })).rejects.toBeInstanceOf(VaultError);
    await c.unlock({ passphrase: 'nueva' });
    expect((await c.getOrCreateMeshKey()).raw).toEqual(mk.raw);
  });
});

describe('browser-safe', () => {
  it('src no usa node:crypto ni Buffer.', () => {
    const walk = (d: string): string[] =>
      readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));
    for (const f of walk('src')) {
      const t = readFileSync(f, 'utf8');
      expect(t, f).not.toContain('node:crypto');
      expect(t, f).not.toContain('Buffer.');
    }
  });
});
