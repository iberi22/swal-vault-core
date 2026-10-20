import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach } from 'vitest';
import { VaultClient, createVaultClient } from '../src/web/vault-client.js';
import { randomBytes, bs, toBase64Url, fromBase64Url, utf8 } from '../src/bytes.js';
import { splitDEK } from '../src/sealedPack.js';

let n = 0;
const client = (extra = {}): VaultClient => createVaultClient({ storage: 'idb', dbName: `tcr${n++}`, pbkdf2Iterations: 310_000, ...extra });

describe('VaultClient Reset Passphrase', () => {
  it('1. End to end forgotten passphrase con recovery share', async () => {
    const dbName = `test-e2e-reset-${n++}`;
    const cA = client({ dbName });
    await cA.unlock({ passphrase: 'old' });
    const mk = await cA.getOrCreateMeshKey();
    const { recoveryShare } = await cA.exportRecoveryShare();
    const secret = new Uint8Array([0x1, 0x2, 0x3]);
    const blob = await cA.wrapBytes(secret);

    const cB = client({ dbName });
    expect(cB.isUnlocked()).toBe(false);
    await expect(cB.unlock({ passphrase: 'x' })).rejects.toMatchObject({ code: 'BAD_KEY' });
    await cB.resetPassphrase(recoveryShare, 'new');

    const cC = client({ dbName });
    await expect(cC.unlock({ passphrase: 'old' })).rejects.toMatchObject({ code: 'BAD_KEY' });
    await cC.unlock({ passphrase: 'new' });
    const mkC = await cC.getOrCreateMeshKey();
    expect(mkC.raw).toEqual(mk.raw);
    const unwrapC = await cC.unwrapBytes(blob);
    expect(unwrapC).toEqual(secret);
  });

  it('2. End to end forgotten passphrase con cloud share', async () => {
    const dbName = `test-e2e-reset-cloud-${n++}`;
    const cA = client({ dbName });
    await cA.unlock({ passphrase: 'old' });
    const mk = await cA.getOrCreateMeshKey();
    const { cloudShare } = await cA.exportRecoveryShare();
    const secret = new Uint8Array([0x4, 0x5, 0x6]);
    const blob = await cA.wrapBytes(secret);

    const cB = client({ dbName });
    expect(cB.isUnlocked()).toBe(false);
    await expect(cB.unlock({ passphrase: 'x' })).rejects.toMatchObject({ code: 'BAD_KEY' });
    await cB.resetPassphrase(cloudShare, 'new');

    const cC = client({ dbName });
    await expect(cC.unlock({ passphrase: 'old' })).rejects.toMatchObject({ code: 'BAD_KEY' });
    await cC.unlock({ passphrase: 'new' });
    const mkC = await cC.getOrCreateMeshKey();
    expect(mkC.raw).toEqual(mk.raw);
    const unwrapC = await cC.unwrapBytes(blob);
    expect(unwrapC).toEqual(secret);
  });

  it('3. Blob created before rotateMeshKey/importMeshKey opens after it', async () => {
    const c = client();
    await c.unlock({ passphrase: 'test' });
    const secret = new Uint8Array([0x9, 0x9, 0x9]);
    const blob = await c.wrapBytes(secret);

    await c.rotateMeshKey();
    expect(await c.unwrapBytes(blob)).toEqual(secret);

    const newRaw = randomBytes(32);
    await c.importMeshKey(newRaw, { replace: true });
    expect(await c.unwrapBytes(blob)).toEqual(secret);
  });

  it('Mutant A & B: rotate -> reissue -> reset with NEW share on locked client works. Same after importMeshKey(replace)', async () => {
    const dbName = `test-mutant-ab-${n++}`;
    const c = client({ dbName });
    await c.unlock({ passphrase: 'old' });
    await c.getOrCreateMeshKey();

    // Rotate -> reissue -> reset with NEW share
    await c.rotateMeshKey();
    const { recoveryShare: newShare1 } = await c.exportRecoveryShare({ reissue: true });

    const c2 = client({ dbName });
    await c2.resetPassphrase(newShare1, 'new');
    await c2.unlock({ passphrase: 'new' });
    expect(c2.isUnlocked()).toBe(true);

    // importMeshKey(replace) -> reissue -> reset with NEW share
    const raw = randomBytes(32);
    await c2.importMeshKey(raw, { replace: true });
    const { recoveryShare: newShare2 } = await c2.exportRecoveryShare({ reissue: true });

    const c3 = client({ dbName });
    await c3.resetPassphrase(newShare2, 'newer');
    await c3.unlock({ passphrase: 'newer' });
    expect(c3.isUnlocked()).toBe(true);
  });

  it('Mutant C: assert meshKeyCheck exists right after getOrCreateMeshKey without passing through unlock', async () => {
    const dbName = `test-mutant-c-${n++}`;
    const c = client({ dbName });
    await c.unlock({ passphrase: 'test' });
    await c.getOrCreateMeshKey(); // Creates meshKeyCheck

    const check = await new Promise((resolve) => {
        const r = indexedDB.open(dbName, 1);
        r.onsuccess = () => {
            const req = r.result.transaction('kv', 'readonly').objectStore('kv').get('meshKeyCheck');
            req.onsuccess = (e: any) => resolve(e.target.result);
        };
    });
    expect(check).toBeDefined();
    expect(typeof check).toBe('string');
  });

  it('Mutant E & Race tests: two clients on the same dbName interleaved with subtle.digest hooks', async () => {
    const dbName = `test-race-${n++}`;

    // Simulate subtle.digest delay hook to interleave operations
    const originalDigest = globalThis.crypto.subtle.digest.bind(globalThis.crypto.subtle);
    let delayDigest = false;

    globalThis.crypto.subtle.digest = async function (alg, data) {
        if (delayDigest && alg === 'SHA-256') {
             await new Promise(r => setTimeout(r, 50));
        }
        return originalDigest(alg, data);
    };

    try {
        // Race 1: getOrCreateMeshKey
        delayDigest = true;
        const c1 = client({ dbName });
        const c2 = client({ dbName });
        await c1.unlock({ passphrase: 'test' });
        await c2.unlock({ passphrase: 'test' });

        const [mk1, mk2] = await Promise.all([
            c1.getOrCreateMeshKey(),
            c2.getOrCreateMeshKey()
        ]);
        expect(mk1.raw).toEqual(mk2.raw); // Must converge to the same DB value

        // Race 3: lazy check in unlock
        delayDigest = false;
        // manually remove meshKeyCheck to test unlock lazy race
        await new Promise<void>((r) => {
            const req = indexedDB.open(dbName, 1);
            req.onsuccess = () => {
                const t = req.result.transaction('kv', 'readwrite');
                t.objectStore('kv').delete('meshKeyCheck');
                t.oncomplete = () => r();
            };
        });

        delayDigest = true;
        const c3 = client({ dbName });
        const c4 = client({ dbName });
        await Promise.all([
            c3.unlock({ passphrase: 'test' }),
            c4.unlock({ passphrase: 'test' })
        ]);

        delayDigest = false;
        const check = await new Promise((resolve) => {
            const r = indexedDB.open(dbName, 1);
            r.onsuccess = () => {
                const req = r.result.transaction('kv', 'readonly').objectStore('kv').get('meshKeyCheck');
                req.onsuccess = (e: any) => resolve(e.target.result);
            };
        });
        expect(check).toBeDefined(); // Must be properly set without crashing

        // Mutant E (Race 2): rotate without CAS
        await c1.rotateMeshKey(); // baseline rotation

        delayDigest = true;
        const rotatePromise1 = c1.rotateMeshKey();
        const rotatePromise2 = c2.rotateMeshKey();

        await expect(Promise.all([rotatePromise1, rotatePromise2])).rejects.toThrow();
        // One must fail with BAD_KEY (concurrent change)
    } finally {
        globalThis.crypto.subtle.digest = originalDigest;
    }
  });

  it('Judge PoC: resetPassphrase concurrent rotation from another tab reverts BAD_KEY', async () => {
     const dbName = `test-reset-rot-${n++}`;
     const c1 = client({ dbName });
     await c1.unlock({ passphrase: 'old' });
     const mk = await c1.getOrCreateMeshKey();
     const rawBlobData = new Uint8Array([0x55, 0x66, 0x77]);
     const blob = await c1.wrapBytes(rawBlobData);
     const { recoveryShare } = await c1.exportRecoveryShare();

     const c2 = client({ dbName });

     // We mock subtle.deriveKey to stall resetPassphrase between the initial read and the final write
     const originalDeriveKey = globalThis.crypto.subtle.deriveKey.bind(globalThis.crypto.subtle);
     let isResetting = false;

     globalThis.crypto.subtle.deriveKey = async function (algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
         if (isResetting && (algorithm as any).name === 'PBKDF2') {
             // In the middle of resetPassphrase deriving new KEK, another client rotates the key
             await c1.rotateMeshKey();
         }
         return originalDeriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages);
     };

     try {
         isResetting = true;
         await expect(c2.resetPassphrase(recoveryShare, 'new')).rejects.toMatchObject({ code: 'BAD_KEY' });
     } finally {
         globalThis.crypto.subtle.deriveKey = originalDeriveKey;
         isResetting = false;
     }

     // Now check that blob can still be unwrapBytes by c1
     const unwrap = await c1.unwrapBytes(blob);
     expect(unwrap).toEqual(rawBlobData);
  });

  it('4. Rotate, reissue, then reset with OLD share on locked client gives BAD_KEY; does not touch DB', async () => {
    const dbName = `test-rot-reissue-${n++}`;
    const c = client({ dbName });
    await c.unlock({ passphrase: 'old' });
    const { recoveryShare: oldShare } = await c.exportRecoveryShare();

    // Rotate and reissue
    await c.rotateMeshKey();
    await c.exportRecoveryShare({ reissue: true });

    // New client instance, locked
    const c2 = client({ dbName });

    // Store raw state before reset
    const beforeMKW = await new Promise((resolve) => {
        const r = indexedDB.open(dbName, 1);
        r.onsuccess = () => {
            const req = r.result.transaction('kv', 'readonly').objectStore('kv').get('meshKeyWrapped');
            req.onsuccess = (e: any) => resolve(e.target.result);
        };
    });
    const beforeKS = await new Promise((resolve) => {
        const r = indexedDB.open(dbName, 1);
        r.onsuccess = () => {
            const req = r.result.transaction('kv', 'readonly').objectStore('kv').get('kekSalt');
            req.onsuccess = (e: any) => resolve(e.target.result);
        };
    });

    await expect(c2.resetPassphrase(oldShare, 'new')).rejects.toMatchObject({ code: 'BAD_KEY' });

    // DB unchanged
    const afterMKW = await new Promise((r) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const get = req.result.transaction('kv', 'readonly').objectStore('kv').get('meshKeyWrapped');
            get.onsuccess = (e: any) => r(e.target.result);
        };
    });
    const afterKS = await new Promise((r) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const get = req.result.transaction('kv', 'readonly').objectStore('kv').get('kekSalt');
            get.onsuccess = (e: any) => r(e.target.result);
        };
    });

    expect(afterMKW).toBe(beforeMKW);
    expect(afterKS).toEqual(beforeKS);

    // 'old' still unlocks
    await c2.unlock({ passphrase: 'old' });
    expect(c2.isUnlocked()).toBe(true);
  });

  it('5. Abort hook on put(meshKeyWrapped) during reset leaves kekSalt intact', async () => {
    const dbName = `test-abort-${n++}`;
    const c = client({ dbName });
    await c.unlock({ passphrase: 'old' });
    const { recoveryShare } = await c.exportRecoveryShare();

    const beforeKS = await new Promise((r) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const get = req.result.transaction('kv', 'readonly').objectStore('kv').get('kekSalt');
            get.onsuccess = (e: any) => r(e.target.result);
        };
    });

    const c2 = client({ dbName });

    // En fake-indexeddb, un throw dentro de put aborta la transaccion entera
    // como lo especifica el estándar.
    let aborted = false;
    const origPut = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function (val: any, key: any) {
        if (key === 'meshKeyWrapped' && typeof val === 'string' && val.includes('v1.')) {
            aborted = true;
            // en fake-indexeddb el método sincrono lanza el error, lo que causa el onerror en IDBRequest
            // Para simular esto tiramos un error standard que abortara la transacción.
            throw new Error('Simulated abort');
        }
        return origPut.apply(this, [val, key]);
    };

    try {
        await expect(c2.resetPassphrase(recoveryShare, 'new')).rejects.toThrow('Simulated abort');
    } finally {
        IDBObjectStore.prototype.put = origPut;
    }

    expect(aborted).toBe(true);

    const afterKS = await new Promise((r) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const get = req.result.transaction('kv', 'readonly').objectStore('kv').get('kekSalt');
            get.onsuccess = (e: any) => r(e.target.result);
        };
    });

    expect(afterKS).toEqual(beforeKS);
  });

  it('6. Legacy vault sin meshKeyCheck se actualiza en unlock', async () => {
    const dbName = `test-legacy-${n++}`;
    const c = client({ dbName });
    await c.unlock({ passphrase: 'old' });
    const { recoveryShare } = await c.exportRecoveryShare();

    // Delete meshKeyCheck directly via IDB
    await new Promise<void>((r) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const t = req.result.transaction('kv', 'readwrite');
            t.objectStore('kv').delete('meshKeyCheck');
            t.oncomplete = () => r();
        };
    });

    const checkBefore = await new Promise((r) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const get = req.result.transaction('kv', 'readonly').objectStore('kv').get('meshKeyCheck');
            get.onsuccess = (e: any) => r(e.target.result);
        };
    });
    expect(checkBefore).toBeUndefined();

    // Re-unlock should recreate meshKeyCheck
    const c2 = client({ dbName });
    await c2.unlock({ passphrase: 'old' });

    const checkAfter = await new Promise((r) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const get = req.result.transaction('kv', 'readonly').objectStore('kv').get('meshKeyCheck');
            get.onsuccess = (e: any) => r(e.target.result);
        };
    });
    expect(checkAfter).toBeDefined();

    // Reset works
    await c2.resetPassphrase(recoveryShare, 'new');
    expect(c2.isUnlocked()).toBe(true);

    // Mutant D: check exists after reset
    const checkAfterReset = await new Promise((r) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const get = req.result.transaction('kv', 'readonly').objectStore('kv').get('meshKeyCheck');
            get.onsuccess = (e: any) => r(e.target.result);
        };
    });
    expect(checkAfterReset).toBeDefined();
  });

  it('7. Reset does not change epoch or recoveryShown', async () => {
    const dbName = `test-epoch-${n++}`;
    const c = client({ dbName });
    await c.unlock({ passphrase: 'old' });
    const { recoveryShare } = await c.exportRecoveryShare();

    const e1 = await c.getEpoch();

    const c2 = client({ dbName });
    await c2.resetPassphrase(recoveryShare, 'new');
    const e2 = await c2.getEpoch();
    expect(e1).toEqual(e2);

    const shown = await new Promise((r) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const get = req.result.transaction('kv', 'readonly').objectStore('kv').get('recoveryShown');
            get.onsuccess = (e: any) => r(e.target.result);
        };
    });
    expect(shown).toBe(true);
  });

  it('8. Reset on empty vault gives NO_MESH_KEY and writes nothing', async () => {
    const dbName = `test-empty-${n++}`;
    const c = client({ dbName });

    // valid fake share format
    const fakeShare = splitDEK(randomBytes(32))[1];

    await expect(c.resetPassphrase(fakeShare, 'new')).rejects.toMatchObject({ code: 'NO_MESH_KEY' });

    // check db is empty
    const count = await new Promise((r) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const get = req.result.transaction('kv', 'readonly').objectStore('kv').getAllKeys();
            get.onsuccess = (e: any) => r(e.target.result.length);
        };
    });
    expect(count).toBe(0);
  });

  it('9. The IndexedDB dump has no 32-byte Uint8Array and secretsKeyWrapped starts with v1.', async () => {
    const dbName = `test-dump-${n++}`;
    const c = client({ dbName });
    await c.unlock({ passphrase: 'test' });
    await c.wrapBytes(new Uint8Array([0x1]));

    const vals = await new Promise<any[]>((r) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const get = req.result.transaction('kv', 'readonly').objectStore('kv').getAll();
            get.onsuccess = (e: any) => r(e.target.result);
        };
    });

    for (const val of vals) {
        if (val instanceof Uint8Array) {
            expect(val.length).not.toBe(32);
        }
    }

    const skw = await new Promise<string>((r) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const get = req.result.transaction('kv', 'readonly').objectStore('kv').get('secretsKeyWrapped');
            get.onsuccess = (e: any) => r(e.target.result);
        };
    });
    expect(skw).toBeDefined();
    expect(skw.startsWith('v1.')).toBe(true);
  });

  it('recoverMeshKey fails properly with BAD_FORMAT when recovery share is empty or malformed', async () => {
    const dbName = `test-bad-rec-${n++}`;
    const c = client({ dbName });
    await c.unlock({ passphrase: 'test' });
    await c.getOrCreateMeshKey();

    // Export device share to ensure the error doesn't hit the NO_MESH_KEY check
    await c.exportRecoveryShare();

    // Call recoverMeshKey with bad shares
    await expect(c.recoverMeshKey(null as any)).rejects.toMatchObject({ code: 'BAD_FORMAT' });
    await expect(c.recoverMeshKey({ index: 2, value: 123 } as any)).rejects.toMatchObject({ code: 'BAD_FORMAT' });
    await expect(c.recoverMeshKey({ index: 2, value: 'invalid_share_value' } as any)).rejects.toMatchObject({ code: 'BAD_FORMAT' });
  });

  it('10. unwrapBytes(wrapKey) gives BAD_KEY; unwrapKey(wrapBytes) gives BAD_KEY; locked vault gives LOCKED', async () => {
    const c = client();
    const raw = randomBytes(32);

    await expect(c.wrapBytes(raw)).rejects.toMatchObject({ code: 'LOCKED' });
    await expect(c.unwrapBytes('v1.a.b')).rejects.toMatchObject({ code: 'LOCKED' });

    await c.unlock({ passphrase: 'test' });

    const wk = await c.wrapKey(raw);
    await expect(c.unwrapBytes(wk)).rejects.toMatchObject({ code: 'BAD_KEY' });

    const wb = await c.wrapBytes(raw);
    await expect(c.unwrapKey(wb)).rejects.toMatchObject({ code: 'BAD_KEY' });
  });
});
