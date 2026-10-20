import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach } from 'vitest';
import { VaultClient, createVaultClient } from '../src/web/vault-client.js';
import { toBase64Url } from '../src/bytes.js';

let n = 0;
const client = (dbName: string): VaultClient => createVaultClient({ storage: 'idb', dbName, pbkdf2Iterations: 310_000 });

describe('VaultClient Concurrency', () => {
  it('1. Unlock vs rotate (stale check)', async () => {
    const dbName = `cc1-${n++}`;
    const c1 = client(dbName);
    await c1.unlock({ passphrase: 'p' });
    await c1.getOrCreateMeshKey();

    // Simula bóveda legacy (borrar meshKeyCheck)
    await new Promise<void>((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readwrite');
            const store = tx.objectStore('kv');
            store.delete('meshKeyCheck');
            tx.oncomplete = () => resolve();
        };
        req.onerror = () => reject(req.error);
    });

    const cA = client(dbName);
    const cB = client(dbName);

    const origDigest = globalThis.crypto.subtle.digest;
    let didRotate = false;
    globalThis.crypto.subtle.digest = async function(this: SubtleCrypto, ...args: Parameters<SubtleCrypto['digest']>) {
        const result = await origDigest.apply(this, args as any);
        const name = typeof args[0] === 'object' ? args[0].name : args[0];
        if (!didRotate && name === 'SHA-256') {
            didRotate = true;
            await cA.unlock({ passphrase: 'p' });
            await cA.rotateMeshKey();
        }
        return result;
    } as typeof globalThis.crypto.subtle.digest;

    try {
        await cB.unlock({ passphrase: 'p' });

        await cA.unlock({ passphrase: 'p' });
        const { recoveryShare } = await cA.exportRecoveryShare({ reissue: true });

        const cT = client(dbName);
        await expect(cT.resetPassphrase(recoveryShare, 'n2')).resolves.toBeUndefined();
    } finally {
        globalThis.crypto.subtle.digest = origDigest;
    }
  });

  it('2. Unlock vs rotate (no false BAD_KEY)', async () => {
    const dbName = `cc2-${n++}`;
    const c1 = client(dbName);
    await c1.unlock({ passphrase: 'p' });
    await c1.getOrCreateMeshKey();

    // Simula bóveda legacy
    await new Promise<void>((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readwrite');
            const store = tx.objectStore('kv');
            store.delete('meshKeyCheck');
            tx.oncomplete = () => resolve();
        };
        req.onerror = () => reject(req.error);
    });

    const cA = client(dbName);
    const cB = client(dbName);

    const origDigest = globalThis.crypto.subtle.digest;
    let didRotate = false;
    globalThis.crypto.subtle.digest = async function(this: SubtleCrypto, ...args: Parameters<SubtleCrypto['digest']>) {
        const result = await origDigest.apply(this, args as any);
        const name = typeof args[0] === 'object' ? args[0].name : args[0];
        if (!didRotate && name === 'SHA-256') {
            didRotate = true;
            await cA.unlock({ passphrase: 'p' });
            await cA.rotateMeshKey();
        }
        return result;
    } as typeof globalThis.crypto.subtle.digest;

    try {
        await cB.unlock({ passphrase: 'p' });
        expect(cB.isUnlocked()).toBe(true);
    } finally {
        globalThis.crypto.subtle.digest = origDigest;
    }
  });

  it('3. Unlock with the wrong passphrase', async () => {
    const dbName = `cc3-${n++}`;
    const c1 = client(dbName);
    await c1.unlock({ passphrase: 'p' });
    await c1.getOrCreateMeshKey();

    // Simula bóveda legacy
    await new Promise<void>((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readwrite');
            const store = tx.objectStore('kv');
            store.delete('meshKeyCheck');
            tx.oncomplete = () => resolve();
        };
        req.onerror = () => reject(req.error);
    });

    const c2 = client(dbName);
    await expect(c2.unlock({ passphrase: 'wrong' })).rejects.toMatchObject({ code: 'BAD_KEY' });

    // Verifica que no escribió check
    const mkc = await new Promise((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readonly');
            const req2 = tx.objectStore('kv').get('meshKeyCheck');
            req2.onsuccess = () => resolve(req2.result);
        };
        req.onerror = () => reject(req.error);
    });
    expect(mkc).toBeUndefined();
  });

  it('4. secretsKey creation vs rotate', async () => {
    const dbName = `cc4-${n++}`;
    const c1 = client(dbName);
    await c1.unlock({ passphrase: 'p' });
    await c1.getOrCreateMeshKey();

    // Borra secretsKeyWrapped
    await new Promise<void>((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readwrite');
            const store = tx.objectStore('kv');
            store.delete('secretsKeyWrapped');
            tx.oncomplete = () => resolve();
        };
        req.onerror = () => reject(req.error);
    });

    const cA = client(dbName);
    await cA.unlock({ passphrase: 'p' });
    const cB = client(dbName);
    await cB.unlock({ passphrase: 'p' });

    const origEncrypt = globalThis.crypto.subtle.encrypt;
    let hookUsed = false;
    let pR: Promise<any>;
    globalThis.crypto.subtle.encrypt = async function(this: SubtleCrypto, ...args: Parameters<SubtleCrypto['encrypt']>) {
        const name = typeof args[0] === 'object' ? args[0].name : args[0];
        if (!hookUsed && name === 'AES-GCM') {
            hookUsed = true;
            pR = cB.rotateMeshKey();
            // let rotate start writing
            await pR.catch(() => {});
        }
        return origEncrypt.apply(this, args as any);
    } as typeof globalThis.crypto.subtle.encrypt;

    let aResult;
    let aError;
    try {
        const pA = cA.wrapBytes(new Uint8Array([1, 2, 3]));
        await Promise.allSettled([pA, pR!]);
        aResult = await pA;
    } catch (e) {
        aError = e;
    } finally {
        globalThis.crypto.subtle.encrypt = origEncrypt;
    }

    // wrapBytes retries the ensure step internally. We should always succeed in this test path.
    expect(aError).toBeUndefined();
    expect(typeof aResult).toBe('string');

    const cC = client(dbName);
    await cC.unlock({ passphrase: 'p' });
    const roundtrip = await cC.unwrapBytes(await cC.wrapBytes(new Uint8Array([1, 2, 3])));
    expect(roundtrip).toEqual(new Uint8Array([1, 2, 3]));
  });

  it('5. wrapBytes vs rotate in the same client (PoC F)', async () => {
    const dbName = `cc5-${n++}`;
    const c = client(dbName);
    await c.unlock({ passphrase: 'p' });

    const [w1, r, w2] = await Promise.allSettled([
        c.wrapBytes(new Uint8Array([1])),
        c.rotateMeshKey(),
        c.wrapBytes(new Uint8Array([2]))
    ]);

    expect(w1.status).toBe('fulfilled');
    expect(r.status).toBe('fulfilled');
    expect(w2.status).toBe('fulfilled');

    const c2 = client(dbName);
    await c2.unlock({ passphrase: 'p' });
    expect(await c2.unwrapBytes((w1 as PromiseFulfilledResult<string>).value)).toEqual(new Uint8Array([1]));
    expect(await c2.unwrapBytes((w2 as PromiseFulfilledResult<string>).value)).toEqual(new Uint8Array([2]));
  });

  it('6. Reset vs rotate (PoC C/D)', async () => {
    const dbName = `cc6-${n++}`;
    const c1 = client(dbName);
    await c1.unlock({ passphrase: 'old' });
    const { recoveryShare } = await c1.exportRecoveryShare();
    const oldBlob = await c1.wrapBytes(new Uint8Array([9, 9]));

    const cA = client(dbName);
    await cA.unlock({ passphrase: 'old' });

    const cR = client(dbName);

    const origDeriveKey = globalThis.crypto.subtle.deriveKey;
    let didRotate = false;
    globalThis.crypto.subtle.deriveKey = async function(this: SubtleCrypto, ...args: Parameters<SubtleCrypto['deriveKey']>) {
        const name = typeof args[0] === 'object' ? args[0].name : args[0];
        if (!didRotate && name === 'PBKDF2') {
            didRotate = true;
            await cA.rotateMeshKey();
        }
        return origDeriveKey.apply(this, args as any);
    } as typeof globalThis.crypto.subtle.deriveKey;

    let resetError;
    try {
        await cR.resetPassphrase(recoveryShare, 'new');
    } catch (e) {
        resetError = e;
    } finally {
        globalThis.crypto.subtle.deriveKey = origDeriveKey;
    }

    expect(resetError).toMatchObject({ code: 'CONFLICT' });
    expect(String((resetError as Error).message)).not.toMatch(/^[A-Za-z0-9_-]+={0,2}$/);

    const mkA = await cA.getOrCreateMeshKey();
    const rawA = mkA.raw;

    const mkw = await new Promise((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readonly');
            const req2 = tx.objectStore('kv').get('meshKeyWrapped');
            req2.onsuccess = () => resolve(req2.result);
        };
        req.onerror = () => reject(req.error);
    });

    // Validar mkw equals rotated
    const cT = client(dbName);
    await cT.unlock({ passphrase: 'old' });
    const mkT = await cT.getOrCreateMeshKey();
    expect(mkT.raw).toEqual(rawA);
    expect(await cT.unwrapBytes(oldBlob)).toEqual(new Uint8Array([9, 9]));
  });

  it('7. Reset vs reset (individual meshKeyWrapped CAS)', async () => {
    const dbName = `cc7-${n++}`;
    const c1 = client(dbName);
    await c1.unlock({ passphrase: 'old' });
    const { recoveryShare } = await c1.exportRecoveryShare();

    const cR1 = client(dbName);
    const cR2 = client(dbName);

    const origDeriveKey = globalThis.crypto.subtle.deriveKey;
    let started = 0;
    let pR2: Promise<void>;
    globalThis.crypto.subtle.deriveKey = async function(this: SubtleCrypto, ...args: Parameters<SubtleCrypto['deriveKey']>) {
        const name = typeof args[0] === 'object' ? args[0].name : args[0];
        if (name === 'PBKDF2') {
            started++;
            if (started === 1) {
                pR2 = cR2.resetPassphrase(recoveryShare, 'p2');
                // wait for r2 to start before proceeding
                await pR2.catch(() => {});
            }
        }
        return origDeriveKey.apply(this, args as any);
    } as typeof globalThis.crypto.subtle.deriveKey;

    let e1, e2;
    try {
        const pR1 = cR1.resetPassphrase(recoveryShare, 'p1');
        const results = await Promise.allSettled([pR1, pR2!]);
        if (results[0].status === 'rejected') e1 = results[0].reason;
        if (results[1].status === 'rejected') e2 = results[1].reason;
    } finally {
        globalThis.crypto.subtle.deriveKey = origDeriveKey;
    }

    expect((e1 ? 1 : 0) + (e2 ? 1 : 0)).toBe(1); // Exactly one rejected
    const error = e1 || e2;
    expect(error).toMatchObject({ code: 'CONFLICT' });

    const winner = e1 ? cR2 : cR1;
    const loser = e1 ? cR1 : cR2;

    await winner.getOrCreateMeshKey(); // Should succeed
    expect(loser.isUnlocked()).toBe(false);
  });

  it('8. Reset vs reissue (individual deviceShare CAS)', async () => {
    const dbName = `cc8-${n++}`;
    const c1 = client(dbName);
    await c1.unlock({ passphrase: 'old' });
    const { recoveryShare } = await c1.exportRecoveryShare();

    const kekSaltBefore = await new Promise((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readonly');
            const req2 = tx.objectStore('kv').get('kekSalt');
            req2.onsuccess = () => resolve(req2.result);
        };
        req.onerror = () => reject(req.error);
    });

    const cA = client(dbName);
    await cA.unlock({ passphrase: 'old' });

    const cR = client(dbName);

    const origDeriveKey = globalThis.crypto.subtle.deriveKey;
    let didReissue = false;
    globalThis.crypto.subtle.deriveKey = async function(this: SubtleCrypto, ...args: Parameters<SubtleCrypto['deriveKey']>) {
        const name = typeof args[0] === 'object' ? args[0].name : args[0];
        if (!didReissue && name === 'PBKDF2') {
            didReissue = true;
            await cA.exportRecoveryShare({ reissue: true });
        }
        return origDeriveKey.apply(this, args as any);
    } as typeof globalThis.crypto.subtle.deriveKey;

    let resetError;
    try {
        await cR.resetPassphrase(recoveryShare, 'new');
    } catch (e) {
        resetError = e;
    } finally {
        globalThis.crypto.subtle.deriveKey = origDeriveKey;
    }

    expect(resetError).toMatchObject({ code: 'CONFLICT' });

    const kekSaltAfter = await new Promise((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readonly');
            const req2 = tx.objectStore('kv').get('kekSalt');
            req2.onsuccess = () => resolve(req2.result);
        };
        req.onerror = () => reject(req.error);
    });

    expect(new Uint8Array(kekSaltAfter as ArrayBuffer)).toEqual(new Uint8Array(kekSaltBefore as ArrayBuffer));
  });

  it('9. Reset vs lazy check (individual meshKeyCheck CAS)', async () => {
    const dbName = `cc9-${n++}`;
    const c1 = client(dbName);
    await c1.unlock({ passphrase: 'old' });
    await c1.getOrCreateMeshKey();
    const { recoveryShare } = await c1.exportRecoveryShare();

    // Legacy vault
    await new Promise<void>((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readwrite');
            const store = tx.objectStore('kv');
            store.delete('meshKeyCheck');
            tx.oncomplete = () => resolve();
        };
        req.onerror = () => reject(req.error);
    });

    const cA = client(dbName);
    const cR = client(dbName);

    const origDeriveKey = globalThis.crypto.subtle.deriveKey;
    let didUnlock = false;
    globalThis.crypto.subtle.deriveKey = async function(this: SubtleCrypto, ...args: Parameters<SubtleCrypto['deriveKey']>) {
        const name = typeof args[0] === 'object' ? args[0].name : args[0];
        if (!didUnlock && name === 'PBKDF2') {
            didUnlock = true;
            await cA.unlock({ passphrase: 'old' });
        }
        return origDeriveKey.apply(this, args as any);
    } as typeof globalThis.crypto.subtle.deriveKey;

    let resetError;
    try {
        await cR.resetPassphrase(recoveryShare, 'new');
    } catch (e) {
        resetError = e;
    } finally {
        globalThis.crypto.subtle.deriveKey = origDeriveKey;
    }

    expect(resetError).toMatchObject({ code: 'CONFLICT' });

    // Retry should succeed
    await cR.resetPassphrase(recoveryShare, 'new');
  });

  it('10. Reset writes the check', async () => {
    const dbName = `cc10-${n++}`;
    const c1 = client(dbName);
    await c1.unlock({ passphrase: 'old' });
    await c1.getOrCreateMeshKey();
    const { recoveryShare } = await c1.exportRecoveryShare();

    // Legacy vault
    await new Promise<void>((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readwrite');
            const store = tx.objectStore('kv');
            store.delete('meshKeyCheck');
            tx.oncomplete = () => resolve();
        };
        req.onerror = () => reject(req.error);
    });

    const cR = client(dbName);
    await cR.resetPassphrase(recoveryShare, 'new');

    const mkc = await new Promise((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readonly');
            const req2 = tx.objectStore('kv').get('meshKeyCheck');
            req2.onsuccess = () => resolve(req2.result);
        };
        req.onerror = () => reject(req.error);
    });
    expect(mkc).toBeDefined();

    const c2 = client(dbName);
    await c2.unlock({ passphrase: 'new' });
    await c2.rotateMeshKey();
    await c2.exportRecoveryShare({ reissue: true });
    const staleShare = recoveryShare; // Now stale

    const cR2 = client(dbName);
    await expect(cR2.resetPassphrase(staleShare, 'n2')).rejects.toMatchObject({ code: 'BAD_KEY' });
  });

  it('11. Malformed share on reset', async () => {
    const dbName = `cc11-${n++}`;
    const c1 = client(dbName);
    await c1.unlock({ passphrase: 'old' });
    await c1.getOrCreateMeshKey();
    await c1.exportRecoveryShare();

    const kekSaltBefore = await new Promise((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readonly');
            const req2 = tx.objectStore('kv').get('kekSalt');
            req2.onsuccess = () => resolve(req2.result);
        };
        req.onerror = () => reject(req.error);
    });
    const mkwBefore = await new Promise((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readonly');
            const req2 = tx.objectStore('kv').get('meshKeyWrapped');
            req2.onsuccess = () => resolve(req2.result);
        };
        req.onerror = () => reject(req.error);
    });

    const cR = client(dbName);

    let errs = [];
    for (const bad of [
        null as any,
        { index: 2, value: 123 } as any,
        { index: 2, value: 'not-base64!' },
        { index: 1, value: 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE' } // device share sized valid base64
    ]) {
        try {
            await cR.resetPassphrase(bad, 'new');
        } catch (e) {
            errs.push(e);
        }
    }

    expect(errs.length).toBe(4);
    for (const e of errs) {
        expect(e).toMatchObject({ code: 'BAD_FORMAT' });
        expect(String((e as Error).message)).not.toMatch(/^[A-Za-z0-9_-]+={0,2}$/);
    }

    const kekSaltAfter = await new Promise((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readonly');
            const req2 = tx.objectStore('kv').get('kekSalt');
            req2.onsuccess = () => resolve(req2.result);
        };
        req.onerror = () => reject(req.error);
    });
    const mkwAfter = await new Promise((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readonly');
            const req2 = tx.objectStore('kv').get('meshKeyWrapped');
            req2.onsuccess = () => resolve(req2.result);
        };
        req.onerror = () => reject(req.error);
    });

    expect(new Uint8Array(kekSaltAfter as ArrayBuffer)).toEqual(new Uint8Array(kekSaltBefore as ArrayBuffer));
    expect(mkwAfter).toBe(mkwBefore);
  });

  it('12. No key bytes in errors check and CONFLICT rejections', async () => {
    const dbName = `cc12-${n++}`;
    const c1 = client(dbName);
    await c1.unlock({ passphrase: 'old' });
    const mk = await c1.getOrCreateMeshKey();
    const { recoveryShare } = await c1.exportRecoveryShare();

    // Simulate bad share with secret key base64
    const badShare = { index: 2, value: recoveryShare.value + 'X' };

    const cR = client(dbName);
    let resetError;
    try {
        await cR.resetPassphrase(badShare, 'new');
    } catch (e) {
        resetError = e;
    }

    expect(resetError).toBeDefined();
    const errMsg = String((resetError as Error).message);

    const mkB64 = toBase64Url(mk.raw);
    expect(errMsg).not.toContain(mkB64);
    expect(errMsg).not.toContain(recoveryShare.value);

    // Add one test each for the CONFLICT code in rotate, import and export
    // to ensure a mutant reverting them to BAD_KEY dies.
    const origWrapWith = globalThis.crypto.subtle.encrypt;
    let hookUsed = false;
    globalThis.crypto.subtle.encrypt = async function(this: SubtleCrypto, ...args: Parameters<SubtleCrypto['encrypt']>) {
        const name = typeof args[0] === 'object' ? args[0].name : args[0];
        if (!hookUsed && name === 'AES-GCM') {
            hookUsed = true;
            // Corrupt the IDB state to trigger CONFLICT
            await new Promise<void>((resolve, reject) => {
              const req = indexedDB.open(dbName, 1);
              req.onsuccess = () => {
                  const db = req.result;
                  const tx = db.transaction('kv', 'readwrite');
                  tx.objectStore('kv').put('stale_data', 'meshKeyWrapped');
                  tx.oncomplete = () => resolve();
              };
              req.onerror = () => reject(req.error);
            });
        }
        return origWrapWith.apply(this, args as any);
    } as typeof globalThis.crypto.subtle.encrypt;

    try {
        const pR = c1.rotateMeshKey();
        await expect(pR).rejects.toMatchObject({ code: 'CONFLICT' });
    } finally {
        globalThis.crypto.subtle.encrypt = origWrapWith;
    }

    // Restore valid state for next hook tests
    const wrapped1 = await c1.wrapKey(mk.raw);
    await new Promise<void>((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readwrite');
            tx.objectStore('kv').put(wrapped1, 'meshKeyWrapped'); // Fake a valid wrapped back
            tx.oncomplete = () => resolve();
        };
        req.onerror = () => reject(req.error);
    });

    const origUnwrap = globalThis.crypto.subtle.decrypt;
    hookUsed = false;
    globalThis.crypto.subtle.decrypt = async function(this: SubtleCrypto, ...args: Parameters<SubtleCrypto['decrypt']>) {
        if (!hookUsed) {
            hookUsed = true;
            await new Promise<void>((resolve, reject) => {
              const req = indexedDB.open(dbName, 1);
              req.onsuccess = () => {
                  const db = req.result;
                  const tx = db.transaction('kv', 'readwrite');
                  tx.objectStore('kv').put('stale_data2', 'meshKeyWrapped');
                  tx.oncomplete = () => resolve();
              };
              req.onerror = () => reject(req.error);
            });
        }
        return origUnwrap.apply(this, args as any);
    } as typeof globalThis.crypto.subtle.decrypt;

    try {
        const pE = c1.exportRecoveryShare();
        await expect(pE).rejects.toMatchObject({ code: 'CONFLICT' });
    } finally {
        globalThis.crypto.subtle.decrypt = origUnwrap;
    }

    // Restore state
    const wrapped2 = await c1.wrapKey(mk.raw);
    await new Promise<void>((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('kv', 'readwrite');
            tx.objectStore('kv').put(wrapped2, 'meshKeyWrapped');
            tx.oncomplete = () => resolve();
        };
        req.onerror = () => reject(req.error);
    });

    const origEncryptI = globalThis.crypto.subtle.encrypt;
    let hookUsedI = false;
    globalThis.crypto.subtle.encrypt = async function(this: SubtleCrypto, ...args: Parameters<SubtleCrypto['encrypt']>) {
        if (!hookUsedI) {
            hookUsedI = true;
            await new Promise<void>((resolve, reject) => {
              const req = indexedDB.open(dbName, 1);
              req.onsuccess = () => {
                  const db = req.result;
                  const tx = db.transaction('kv', 'readwrite');
                  tx.objectStore('kv').put('stale_data3', 'meshKeyWrapped');
                  tx.oncomplete = () => resolve();
              };
              req.onerror = () => reject(req.error);
            });
        }
        return origEncryptI.apply(this, args as any);
    } as typeof globalThis.crypto.subtle.encrypt;

    try {
        const pI = c1.importMeshKey(mk.raw, { replace: true });
        await expect(pI).rejects.toMatchObject({ code: 'CONFLICT' });
    } finally {
        globalThis.crypto.subtle.encrypt = origEncryptI;
    }
  });
});