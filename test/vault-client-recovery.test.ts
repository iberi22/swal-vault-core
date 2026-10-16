import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { createVaultClient, VaultError, type VaultClient } from '../src/web/vault-client.js';
import { splitDEK } from '../src/sealedPack.js';
import { randomBytes } from '../src/bytes.js';

function getClient(dbName: string = 'swal-vault'): VaultClient {
  return createVaultClient({
    storage: 'idb',
    dbName,
    pbkdf2Iterations: 310_000,
  });
}

describe('VaultClient recovery', () => {
  let c1: VaultClient;
  let c2: VaultClient;

  beforeEach(async () => {
    c1 = getClient('db1');
    c2 = getClient('db2'); // Simulate device loss / new device
  });

  afterEach(() => {
    c1.lock();
    c2.lock();
  });

  it('recoverMeshKeyFromShares works with (1,2), (1,3), (2,3) returning same bytes', async () => {
    await c1.unlock({ passphrase: 'test' });
    const mk = await c1.getOrCreateMeshKey();
    const shares = splitDEK(mk.raw);

    const s1 = shares[0];
    const s2 = shares[1];
    const s3 = shares[2];

    const r12 = await c1.recoverMeshKeyFromShares(s1, s2);
    const r13 = await c1.recoverMeshKeyFromShares(s1, s3);
    const r23 = await c1.recoverMeshKeyFromShares(s2, s3);

    expect(r12).toEqual(mk.raw);
    expect(r13).toEqual(mk.raw);
    expect(r23).toEqual(mk.raw);
  });

  it('recoverMeshKeyFromShares fails with duplicated index', async () => {
    const raw = randomBytes(32);
    const shares = splitDEK(raw);
    await expect(c1.recoverMeshKeyFromShares(shares[0], shares[0])).rejects.toMatchObject({ code: 'BAD_PARAMS' });
  });

  it('recoverMeshKeyFromShares fails with out-of-range index', async () => {
    const raw = randomBytes(32);
    const shares = splitDEK(raw);
    const badShare = { index: 4, value: shares[0].value };
    await expect(c1.recoverMeshKeyFromShares(shares[0], badShare)).rejects.toMatchObject({ code: 'BAD_PARAMS' });
  });

  it('recoverMeshKeyFromShares fails with bad format share', async () => {
    const raw = randomBytes(32);
    const shares = splitDEK(raw);
    const badShare = { index: 2, value: 'invalid_base64_string_xyz!' };
    await expect(c1.recoverMeshKeyFromShares(shares[0], badShare)).rejects.toMatchObject({ code: 'BAD_FORMAT' });
  });

  it('recoverMeshKeyFromShares works on empty client (simulating device loss)', async () => {
    await c1.unlock({ passphrase: 'test' });
    const mk = await c1.getOrCreateMeshKey();
    const shares = splitDEK(mk.raw);

    // c2 is new device, has empty idb, is not unlocked
    const recovered = await c2.recoverMeshKeyFromShares(shares[0], shares[2]);
    expect(recovered).toEqual(mk.raw);
  });

  it('importMeshKey into empty vault works, and getOrCreateMeshKey returns those bytes', async () => {
    await c2.unlock({ passphrase: 'test2' });
    const raw = randomBytes(32);
    await c2.importMeshKey(raw);
    const mk = await c2.getOrCreateMeshKey();
    expect(mk.raw).toEqual(raw);
  });

  it('importMeshKey without replace over an existing key throws BAD_PARAMS', async () => {
    await c1.unlock({ passphrase: 'test' });
    const mk = await c1.getOrCreateMeshKey();
    const raw2 = randomBytes(32);
    await expect(c1.importMeshKey(raw2)).rejects.toMatchObject({ code: 'BAD_PARAMS' });

    // Stored key is unchanged
    const mk2 = await c1.getOrCreateMeshKey();
    expect(mk2.raw).toEqual(mk.raw);
  });

  it('importMeshKey with replace makes previous recovery shares unusable', async () => {
    await c1.unlock({ passphrase: 'test' });
    await c1.getOrCreateMeshKey();
    const { recoveryShare } = await c1.exportRecoveryShare();

    const raw2 = randomBytes(32);
    await c1.importMeshKey(raw2, { replace: true });

    const mk2 = await c1.getOrCreateMeshKey();
    expect(mk2.raw).toEqual(raw2);

    // Old deviceShare is deleted, so recoverMeshKey (which uses deviceShare) will fail
    await expect(c1.recoverMeshKey(recoveryShare)).rejects.toMatchObject({ code: 'NO_MESH_KEY' });
  });

  it('locked vault refuses importMeshKey with LOCKED', async () => {
    const raw = randomBytes(32);
    await expect(c2.importMeshKey(raw)).rejects.toMatchObject({ code: 'LOCKED' });
  });

  it('raw key bytes never appear in IndexedDB values', async () => {
    const c3 = getClient('db3');
    await c3.unlock({ passphrase: 'test' });
    const raw = randomBytes(32);
    await c3.importMeshKey(raw);

    // We check IndexedDB directly using the API provided to fake-indexeddb
    const req = indexedDB.open('db3');
    const db = await new Promise<IDBDatabase>((res, rej) => {
      req.onsuccess = () => res(req.result);
      req.onerror = () => rej(req.error);
    });

    const tx = db.transaction('kv', 'readonly');
    const store = tx.objectStore('kv');
    const allReq = store.getAll();
    const vals = await new Promise<any[]>((res, rej) => {
      allReq.onsuccess = () => res(allReq.result);
      allReq.onerror = () => rej(allReq.error);
    });

    for (const val of vals) {
      if (val instanceof Uint8Array) {
        expect(val).not.toContain(raw);
      } else if (typeof val === 'string') {
        const rawStr = Array.from(raw).map(b => String.fromCharCode(b)).join('');
        expect(val).not.toContain(rawStr);
        expect(val === rawStr).toBe(false);
      }
    }
  });

  it('importMeshKey with bad length throws BAD_PARAMS', async () => {
    await c1.unlock({ passphrase: 'test' });
    const badRaw = randomBytes(31);
    await expect(c1.importMeshKey(badRaw)).rejects.toMatchObject({ code: 'BAD_PARAMS' });
  });
});
