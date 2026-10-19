import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach } from 'vitest';
import { VaultClient, VaultClientOptions, VaultError, createVaultClient } from '../src/web/vault-client.js';
import { randomBytes, bs, toBase64Url, fromBase64Url } from '../src/bytes.js';

let n = 0;
// Helper function to create client like in vault.test.ts
const client = (extra = {}): VaultClient => createVaultClient({ storage: 'idb', dbName: `twb${n++}`, pbkdf2Iterations: 310_000, ...extra });

describe('VaultClient wrapBytes and unwrapBytes', () => {
  let c: VaultClient;

  beforeEach(() => {
    c = client();
  });

  it('round trip para 1 byte', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw = new Uint8Array([0x42]);
    const wrapped = await c.wrapBytes(raw);
    expect(await c.unwrapBytes(wrapped)).toEqual(raw);
  });

  it('round trip para 32 bytes', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw = randomBytes(32);
    const wrapped = await c.wrapBytes(raw);
    expect(await c.unwrapBytes(wrapped)).toEqual(raw);
  });

  it('round trip para 2400 bytes (ML-KEM-768 secret key)', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw = randomBytes(2400);
    const wrapped = await c.wrapBytes(raw);
    expect(await c.unwrapBytes(wrapped)).toEqual(raw);
  });

  it('round trip para 4032 bytes (ML-DSA-65 secret key)', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw = randomBytes(4032);
    const wrapped = await c.wrapBytes(raw);
    expect(await c.unwrapBytes(wrapped)).toEqual(raw);
  });

  it('round trip para 65536 bytes (max permitido)', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw = randomBytes(65536);
    const wrapped = await c.wrapBytes(raw);
    expect(await c.unwrapBytes(wrapped)).toEqual(raw);
  });

  it('0 bytes falla con BAD_PARAMS', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw = new Uint8Array(0);
    expect(() => c.wrapBytes(raw)).toThrow(VaultError);
    try {
      c.wrapBytes(raw);
    } catch (e: any) {
      expect(e.code).toBe('BAD_PARAMS');
    }
  });

  it('65537 bytes falla con BAD_PARAMS', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw = new Uint8Array(65537); // Do not use randomBytes(65537) because getRandomValues has a 65536 quota limit
    expect(() => c.wrapBytes(raw)).toThrow(VaultError);
    try {
      c.wrapBytes(raw);
    } catch (e: any) {
      expect(e.code).toBe('BAD_PARAMS');
    }
  });

  it('ciphertext alterado falla con BAD_KEY', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw = randomBytes(32);
    let wrapped = await c.wrapBytes(raw);
    // alter last character
    wrapped = wrapped.substring(0, wrapped.length - 1) + (wrapped.endsWith('A') ? 'B' : 'A');
    await expect(c.unwrapBytes(wrapped)).rejects.toMatchObject({ code: 'BAD_KEY' });
  });

  it('string malformado falla con BAD_FORMAT', async () => {
    await c.unlock({ passphrase: 'test' });
    const badStrings = [
      'v1.test',
      'v2.test.test',
      'test.test.test'
    ];
    for (const bad of badStrings) {
      // unwrapBytes returns Promise, bad strings cause sync throw or async reject depending on implementation
      // wait, unwrapBytes is `(wrapped) => unwrapWith(wrapped, needKek())`
      // if needKek() passes, unwrapWith is async but parts.length !== 3 throws sync.
      // let's use both.
      try {
        await c.unwrapBytes(bad);
        throw new Error('should have thrown');
      } catch (e: any) {
        expect(e.code).toBe('BAD_FORMAT');
      }
    }
  });

  it('vault bloqueado falla con LOCKED', async () => {
    expect(c.isUnlocked()).toBe(false);
    const raw = randomBytes(16);
    expect(() => c.wrapBytes(raw)).toThrow(VaultError);
    try {
      c.wrapBytes(raw);
    } catch (e: any) {
      expect(e.code).toBe('LOCKED');
    }

    expect(() => c.unwrapBytes('v1.a.b')).toThrow(VaultError);
    try {
      c.unwrapBytes('v1.a.b');
    } catch (e: any) {
      expect(e.code).toBe('LOCKED');
    }
  });

  it('salida envuelta varia entre llamadas (IV fresco), pero desenvuelve al mismo plaintext', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw = randomBytes(32);
    const wrapped1 = await c.wrapBytes(raw);
    const wrapped2 = await c.wrapBytes(raw);
    expect(wrapped1).not.toBe(wrapped2);
    expect(await c.unwrapBytes(wrapped1)).toEqual(raw);
    expect(await c.unwrapBytes(wrapped2)).toEqual(raw);
  });

  it('wrapKey sigue rechazando entradas de 64 bytes con BAD_PARAMS', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw64 = randomBytes(64);
    expect(() => c.wrapKey(raw64)).toThrow(VaultError);
    try {
      c.wrapKey(raw64);
    } catch (e: any) {
      expect(e.code).toBe('BAD_PARAMS');
    }

    const raw32 = randomBytes(32);
    const wrapped32 = await c.wrapKey(raw32);
    expect(await c.unwrapKey(wrapped32)).toEqual(raw32);
  });
});
