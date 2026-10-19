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

import { MemoryCloudShareStore, R2StorageClient, storeCloudShare, registerOnPolygon, PACK_VERSION } from '../src/index.js';
import { bs, fromBase64, toBase64, utf8, concatBytes } from '../src/bytes.js';

const flip = (b64: string) => { const b = fromBase64(b64); b[0] ^= 1; return toBase64(b); };

describe('propiedades Shamir', () => {
  it('cualquier par de 3 reconstruye (200 DEK aleatorias) y una share sola no', () => {
    for (let i = 0; i < 200; i++) {
      const dek = randomBytes(32);
      const s = splitDEK(dek);
      for (const [a, b] of [[0, 1], [0, 2], [1, 2], [1, 0], [2, 1], [2, 0]]) expect(reconstructDEK([s[a], s[b]])).toEqual(dek);
      expect(() => reconstructDEK([s[0]])).toThrow();
      expect(() => reconstructDEK([s[1], s[1]])).toThrow();
      // una share sola no da informacion directa: usarla como "DEK" con otra falsa no reconstruye
      expect(reconstructDEK([s[0], { index: 2, value: toBase64(randomBytes(32)), v: 3 }])).not.toEqual(dek);
    }
  });
});

describe('AAD y manipulacion (V6)', () => {
  const payload = utf8('secreto');
  it('pack v2 con metadatos: rechaza metadata, tag, ciphertext, iv y v alterados', async () => {
    const pack = await createSealedPack(payload, { entity: 'x', appId: 'a', timestamp: 5 });
    expect(pack.v).toBe(PACK_VERSION);
    const sh = pack.shares.slice(0, 2);
    expect(await unpackSealedPack(pack, sh)).toEqual(payload);
    await expect(unpackSealedPack({ ...pack, metadata: { ...pack.metadata, appId: 'b' } }, sh)).rejects.toBeDefined();
    await expect(unpackSealedPack({ ...pack, metadata: { ...pack.metadata, extra: 1 } }, sh)).rejects.toBeDefined();
    await expect(unpackSealedPack({ ...pack, tag: flip(pack.tag) }, sh)).rejects.toBeDefined();
    await expect(unpackSealedPack({ ...pack, ciphertext: flip(pack.ciphertext) }, sh)).rejects.toBeDefined();
    await expect(unpackSealedPack({ ...pack, iv: flip(pack.iv) }, sh)).rejects.toBeDefined();
    const { v: _v, ...downgraded } = pack; // quitar `v` para saltar el AAD
    await expect(unpackSealedPack(downgraded as any, sh)).rejects.toBeDefined();
    await expect(unpackSealedPack({ ...pack, v: 99 }, sh)).rejects.toThrow(/Version/);
    await expect(unpackSealedPack(pack, [pack.shares[0], { ...pack.shares[1], value: flip(pack.shares[1].value) }])).rejects.toBeDefined();
  });
  it('lista blanca de metadatos en claro', async () => {
    await expect(createSealedPack(payload, { timestamp: 1, nombre: 'Ana' })).rejects.toThrow(/lista blanca/);
    const p = await createSealedPack(payload, { timestamp: 1, nombre: 'Ana' }, undefined, { extraClearKeys: ['nombre'] });
    expect(await unpackSealedPack(p, p.shares.slice(1))).toEqual(payload);
  });
  it('lee packs legado (sin v, sin AAD)', async () => {
    const dek = randomBytes(32), iv = randomBytes(12);
    const key = await globalThis.crypto.subtle.importKey('raw', bs(dek), 'AES-GCM', false, ['encrypt']);
    const sealed = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: bs(iv), tagLength: 128 }, key, bs(payload)));
    const ct = sealed.subarray(0, sealed.length - 16), tag = sealed.subarray(sealed.length - 16);
    const pack: any = {
      id: 'legacy', content_hash: await computeContentHashAsync(ct, meta), ciphertext: toBase64(ct), iv: toBase64(iv),
      tag: toBase64(tag), shares: splitDEK(dek, 2), signature: '', publicKey: '', metadata: meta, chain: 'polygon', chainId: 137,
    };
    expect(await unpackSealedPack(pack, pack.shares.slice(0, 2))).toEqual(payload);
  });
  it('compatibilidad Node webcrypto <-> vault (AAD v2)', async () => {
    const p = await createSealedPack(payload, meta);
    const dek = reconstructDEK(p.shares.slice(1));
    const key = await globalThis.crypto.subtle.importKey('raw', bs(dek), 'AES-GCM', false, ['decrypt']);
    const aad = utf8(`swal-vault/v3|{"entity":"x","timestamp":1}`);
    const dec = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bs(fromBase64(p.iv)), tagLength: 128, additionalData: bs(aad) }, key, bs(concatBytes(fromBase64(p.ciphertext), fromBase64(p.tag))));
    expect(new Uint8Array(dec)).toEqual(payload);
  });
});

describe('frontera de nube (V1/V8/V9)', () => {
  it('uploadSealedPack rechaza >=2 shares y nunca sube shares', async () => {
    const pack = await createSealedPack(utf8('x'), meta);
    const puts: string[] = [];
    const r2 = new R2StorageClient({ r2Binding: { put: async (_k: string, body: string) => { puts.push(body); } } });
    await expect(r2.uploadSealedPack(pack)).rejects.toThrow(/E2EE/);
    await expect(r2.uploadSealedPack({ ...pack, shares: pack.shares.slice(0, 2) })).rejects.toThrow(/E2EE/);
    expect(puts.length).toBe(0);
    const { key } = await r2.uploadSealedPack({ ...pack, shares: [pack.shares[2]] });
    expect(JSON.parse(puts[0]).shares).toEqual([]);
    expect((await r2.getSealedPack(key))!.shares).toEqual([]);
    await r2.uploadSealedPack({ ...pack, shares: [] });
  });
  it('CloudShareStore guarda solo x=3; registerOnPolygon no esta implementado', async () => {
    const pack = await createSealedPack(utf8('x'), meta);
    const st = new MemoryCloudShareStore();
    await storeCloudShare(st, pack);
    expect((await st.get(pack.id))!.index).toBe(3);
    await expect(st.put('z', pack.shares[0])).rejects.toThrow();
    await expect(storeCloudShare(st, { ...pack, shares: [pack.shares[0]] })).rejects.toThrow();
    expect(() => registerOnPolygon(pack)).toThrow(/not implemented/);
  });
});
