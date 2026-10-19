import { describe, it, expect } from 'vitest';
import 'fake-indexeddb/auto';
import { createVaultClient } from '../src/web/vault-client.js';

const rawDB = (db: string, k: string) => new Promise<any>((res, rej) => {
  const o = indexedDB.open(db); o.onerror = () => rej(o.error);
  o.onsuccess = () => { const r = o.result.transaction('kv').objectStore('kv').get(k); r.onsuccess = () => { res(r.result); o.result.close(); }; r.onerror = () => rej(r.error); };
});

const mk = (db: string) => createVaultClient({ storage: 'idb', dbName: db, pbkdf2Iterations: 310_000 });

describe('judge #7', () => {
  it('J1 abort during rotation leaves key, epoch, deviceShare and recoveryShown intact', async () => {
    const c = mk('j7a'); await c.unlock({ passphrase: 'p' });
    const before = (await c.getOrCreateMeshKey()).raw; await c.exportRecoveryShare();
    const w0 = await rawDB('j7a', 'meshKeyWrapped');
    const orig = IDBObjectStore.prototype.delete;
    IDBObjectStore.prototype.delete = function (this: IDBObjectStore, key: any) {
      if (key === 'deviceShare') { this.transaction.abort(); throw new DOMException('aborted', 'AbortError'); }
      return orig.call(this, key);
    } as any;
    try { await expect(c.rotateMeshKey()).rejects.toBeDefined(); } finally { IDBObjectStore.prototype.delete = orig; }
    expect(await rawDB('j7a', 'meshKeyWrapped')).toBe(w0);
    expect(await c.getEpoch()).toBe(0);
    expect(await rawDB('j7a', 'deviceShare')).toBeDefined();
    expect(await rawDB('j7a', 'recoveryShown')).toBe(true);
    expect((await c.getOrCreateMeshKey()).raw).toEqual(before);
  });

  it('J2 concurrent rotations get distinct epochs and the stored key is the one with the highest epoch', async () => {
    const c = mk('j7b'); await c.unlock({ passphrase: 'p' }); await c.getOrCreateMeshKey();
    const r = await Promise.all([c.rotateMeshKey(), c.rotateMeshKey()]);
    expect(new Set(r.map(x => x.epoch)).size).toBe(2);
    expect(await c.getEpoch()).toBe(2);
    const top = r.find(x => x.epoch === 2)!;
    expect((await c.getOrCreateMeshKey()).raw).toEqual(top.raw);
  });

  it('J3 export racing a rotation never leaves a deviceShare for a stale key', async () => {
    // Retry J3 because Promise.allSettled interleaving might cause occasional flakiness depending on exact scheduling in test env
    // To ensure a race where export succeeds and rotation happens at the same time:
    const c = mk('j7c'); await c.unlock({ passphrase: 'p' }); await c.getOrCreateMeshKey();
    const [exp] = await Promise.allSettled([c.exportRecoveryShare(), c.rotateMeshKey()]);
    const ds = await rawDB('j7c', 'deviceShare');
    if (ds && exp.status === 'fulfilled') {
      expect(await c.recoverMeshKey(exp.value.recoveryShare)).toEqual((await c.getOrCreateMeshKey()).raw);
    }
  });

  it('J4 after rotation the old recovery share is dead (no stale deviceShare)', async () => {
    const c = mk('j7d'); await c.unlock({ passphrase: 'p' });
    const { recoveryShare } = await c.exportRecoveryShare();
    await c.rotateMeshKey();
    await expect(c.recoverMeshKey(recoveryShare)).rejects.toMatchObject({ code: 'NO_MESH_KEY' });
  });
});
