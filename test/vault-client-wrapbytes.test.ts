import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach } from 'vitest';
import { VaultClient, VaultClientOptions, VaultError, createVaultClient } from '../src/web/vault-client.js';
import { randomBytes, bs, toBase64Url, fromBase64Url, utf8 } from '../src/bytes.js';

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
    await expect(c.wrapBytes(raw)).rejects.toMatchObject({ code: 'BAD_PARAMS' });
  });

  it('65537 bytes falla con BAD_PARAMS', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw = new Uint8Array(65537); // Do not use randomBytes(65537) because getRandomValues has a 65536 quota limit
    await expect(c.wrapBytes(raw)).rejects.toMatchObject({ code: 'BAD_PARAMS' });
  });

  it('Uint32Array, null, string fail with BAD_PARAMS or BAD_FORMAT without TypeError', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw32 = new Uint32Array(65536);
    await expect(c.wrapBytes(raw32 as any)).rejects.toMatchObject({ code: 'BAD_PARAMS' });
    await expect(c.wrapBytes(null as any)).rejects.toMatchObject({ code: 'BAD_PARAMS' });
    await expect(c.wrapBytes('abc' as any)).rejects.toMatchObject({ code: 'BAD_PARAMS' });
    await expect(c.unwrapBytes(123 as any)).rejects.toMatchObject({ code: 'BAD_FORMAT' });
  });

  it('ciphertext alterado falla con BAD_KEY', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw = randomBytes(32);
    let wrapped = await c.wrapBytes(raw);
    // alter last character
    wrapped = wrapped.substring(0, wrapped.length - 1) + (wrapped.endsWith('A') ? 'B' : 'A');
    await expect(c.unwrapBytes(wrapped)).rejects.toMatchObject({ code: 'BAD_KEY' });
  });

  it('IV manipulado falla con BAD_KEY', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw = randomBytes(32);
    let wrapped = await c.wrapBytes(raw);
    const parts = wrapped.split('.');
    parts[1] = parts[1].substring(0, parts[1].length - 1) + (parts[1].endsWith('A') ? 'B' : 'A');
    await expect(c.unwrapBytes(parts.join('.'))).rejects.toMatchObject({ code: 'BAD_KEY' });
  });

  it('string malformado falla con BAD_FORMAT', async () => {
    await c.unlock({ passphrase: 'test' });
    const badStrings = [
      '',
      'v1.test',
      'v2.test.test',
      'test.test.test',
      'v1.a.b.c'
    ];
    for (const bad of badStrings) {
      await expect(c.unwrapBytes(bad)).rejects.toMatchObject({ code: 'BAD_FORMAT' });
    }
  });

  it('vault bloqueado falla con LOCKED', async () => {
    expect(c.isUnlocked()).toBe(false);
    const raw = randomBytes(16);
    await expect(c.wrapBytes(raw)).rejects.toMatchObject({ code: 'LOCKED' });
    await expect(c.unwrapBytes('v1.a.b')).rejects.toMatchObject({ code: 'LOCKED' });
  });

  it('wrong-KEK (dos clientes, distinto passphrase)', async () => {
    await c.unlock({ passphrase: 'test' });
    const wrapped = await c.wrapBytes(randomBytes(32));
    const c2 = client();
    await c2.unlock({ passphrase: 'test2' });
    await expect(c2.unwrapBytes(wrapped)).rejects.toMatchObject({ code: 'BAD_KEY' });
  });

  it('compatibilidad wrapKey y wrapBytes', async () => {
    await c.unlock({ passphrase: 'test' });
    const raw = randomBytes(32);
    const wrappedBytes = await c.wrapBytes(raw);
    expect(await c.unwrapKey(wrappedBytes)).toEqual(raw);

    const wrappedKey = await c.wrapKey(raw);
    expect(await c.unwrapBytes(wrappedKey)).toEqual(raw);
  });

  it('pins v1 envelope path sin AAD, independiente, usando subtle', async () => {
    // 1. Setup client and unlock
    const st = {
      store: new Map<string, any>(),
      get: async (k: string) => st.store.get(k),
      put: async (k: string, v: any) => { st.store.set(k, v); }
    };

    // Create specific salt and write to indexeddb logic manually via client initialization side effect
    // We can't easily mock IDB, so let's do real client unlock, then read salt from its internal store? No, VaultClient doesn't expose IDB.
    // Instead we can use IDB direct access or reconstruct KEK derivation
    const subtle = globalThis.crypto.subtle;
    const s = randomBytes(16);
    // write to DB that client uses
    const req = indexedDB.open((c as any).dbName || `twb${n-1}`, 1);
    await new Promise<void>((resolve, reject) => {
      req.onupgradeneeded = () => req.result.createObjectStore('kv');
      req.onsuccess = () => {
        const t = req.result.transaction('kv', 'readwrite');
        t.objectStore('kv').put(s, 'kekSalt');
        t.oncomplete = () => resolve();
        t.onerror = () => reject(req.error);
      };
      req.onerror = () => reject(req.error);
    });

    await c.unlock({ passphrase: 'pin' });
    const raw = new Uint8Array([0x11, 0x22, 0x33]);
    const wrapped = await c.wrapBytes(raw);

    // derive independent KEK
    const base = await subtle.importKey('raw', bs(utf8('pin'.normalize('NFKC'))), 'PBKDF2', false, ['deriveKey']);
    const kek = await subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt: bs(s), iterations: 310_000 },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    // test decrypt WITHOUT AAD
    const parts = wrapped.split('.');
    const iv = fromBase64Url(parts[1]);
    expect(iv.length).toBe(12); // assert IV is 12 bytes
    const ct = fromBase64Url(parts[2]);

    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: bs(iv) }, // no additionalData
      kek,
      bs(ct)
    );
    expect(new Uint8Array(pt)).toEqual(raw);

    // test reverse: hand encrypt blob without AAD
    const newIv = randomBytes(12);
    const newRaw = new Uint8Array([0xAA, 0xBB]);
    const newCt = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: bs(newIv) }, kek, bs(newRaw)));
    const newWrapped = `v1.${toBase64Url(newIv)}.${toBase64Url(newCt)}`;

    expect(await c.unwrapBytes(newWrapped)).toEqual(newRaw);

    // Mutants that must fail
    // 1. AAD added
    const ctAAD = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: bs(newIv), additionalData: bs(utf8('aad')) }, kek, bs(newRaw)));
    const wrappedAAD = `v1.${toBase64Url(newIv)}.${toBase64Url(ctAAD)}`;
    await expect(c.unwrapBytes(wrappedAAD)).rejects.toMatchObject({ code: 'BAD_KEY' });

    // 2. IV length 16
    const iv16 = randomBytes(16);
    const ct16 = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: bs(iv16) }, kek, bs(newRaw)));
    const wrapped16 = `v1.${toBase64Url(iv16)}.${toBase64Url(ct16)}`;
    await expect(c.unwrapBytes(wrapped16)).rejects.toMatchObject({ code: 'BAD_FORMAT' }); // or BAD_KEY depending on implementation, prompt asked to fail
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
