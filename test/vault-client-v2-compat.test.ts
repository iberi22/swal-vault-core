
import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { createVaultClient } from '../src/web/vault-client.js';
import { splitDEK } from '../src/sealedPack.js';

describe('VaultClient recovery v2 compatibility', () => {
  it('stores a v2 deviceShare without v in IDB and recoverMeshKey returns original key', async () => {
    const c = createVaultClient({ storage: 'idb', dbName: 't-v2-recovery2' });
    await c.unlock({ passphrase: 'pw' });
    const mk = await c.getOrCreateMeshKey();

    // Generate v2 shares for the mesh key
    const shares = splitDEK(mk.raw, 2);
    const deviceShare = shares[0];
    const recoveryShare = shares[1];

    // Remove v to mock legacy
    delete deviceShare.v;
    delete recoveryShare.v;

    // Overwrite deviceShare in IDB
    const open = indexedDB.open('t-v2-recovery2');
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(open.error);
    });

    const tx2 = db.transaction('kv', 'readwrite');
    await new Promise((resolve) => {
      tx2.objectStore('kv').put(deviceShare, 'deviceShare');
      tx2.oncomplete = resolve;
    });

    // Recover
    const recovered = await c.recoverMeshKey(recoveryShare);
    expect(recovered).toEqual(mk.raw);
  });
});
