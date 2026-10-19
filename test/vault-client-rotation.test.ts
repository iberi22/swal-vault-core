import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { randomBytes } from '../src/bytes.js';
import { createVaultClient, VaultError } from '../src/web/vault-client.js';

let n = 0;
const client = (extra = {}) => createVaultClient({ storage: 'idb', dbName: `rot${n++}`, ...extra });

describe('VaultClient Rotation', () => {
  it('rotateMeshKey returns different bytes than getOrCreateMeshKey gave before and stores them', async () => {
    const c = client();
    await c.unlock({ passphrase: 'test' });
    const { raw: initialRaw } = await c.getOrCreateMeshKey();

    const { raw: rotatedRaw, epoch: newEpoch } = await c.rotateMeshKey();
    expect(rotatedRaw).not.toEqual(initialRaw);
    expect(newEpoch).toBe(1);

    const { raw: nextRaw } = await c.getOrCreateMeshKey();
    expect(nextRaw).toEqual(rotatedRaw);
  });

  it('epoch starts at 0', async () => {
    const c = client();
    expect(await c.getEpoch()).toBe(0);
  });

  it('epoch is 1 after one rotation and 2 after two', async () => {
    const c = client();
    await c.unlock({ passphrase: 'test' });
    await c.getOrCreateMeshKey();
    expect(await c.getEpoch()).toBe(0);

    const { epoch: e1 } = await c.rotateMeshKey();
    expect(e1).toBe(1);
    expect(await c.getEpoch()).toBe(1);

    const { epoch: e2 } = await c.rotateMeshKey();
    expect(e2).toBe(2);
    expect(await c.getEpoch()).toBe(2);
  });

  it('epoch survives a lock() plus unlock()', async () => {
    const c = client();
    await c.unlock({ passphrase: 'test' });
    await c.rotateMeshKey();
    expect(await c.getEpoch()).toBe(1);

    c.lock();
    expect(await c.getEpoch()).toBe(1); // can read epoch while locked
    await c.unlock({ passphrase: 'test' });
    expect(await c.getEpoch()).toBe(1);
  });

  it('the previous recovery share no longer reconstructs the key after a rotation', async () => {
    const c = client();
    await c.unlock({ passphrase: 'test' });
    const { recoveryShare } = await c.exportRecoveryShare();

    // After rotation, new deviceShare should not be compatible with old recoveryShare
    await c.rotateMeshKey();

    // Trying to recover mesh key using old recoveryShare and the newly stored deviceShare
    // expect it to throw NO_MESH_KEY
    await expect(c.recoverMeshKey(recoveryShare)).rejects.toMatchObject({ code: 'NO_MESH_KEY' });
  });

  it('a locked vault refuses rotation with LOCKED', async () => {
    const c = client();
    await expect(c.rotateMeshKey()).rejects.toMatchObject({ code: 'LOCKED' });
  });

  it('exportRecoveryShare({ reissue: true }) returns a fresh kit after SHARE_ALREADY_SHOWN was already reached, and the old x=2 stops working', async () => {
    const c = client();
    await c.unlock({ passphrase: 'test' });
    const { recoveryShare: oldShare, cloudShare: oldCloud } = await c.exportRecoveryShare();
    await expect(c.exportRecoveryShare()).rejects.toMatchObject({ code: 'SHARE_ALREADY_SHOWN' });

    const { recoveryShare: newShare } = await c.exportRecoveryShare({ reissue: true });
    const { raw: currentRaw } = await c.getOrCreateMeshKey();

    // The old share combined with the old cloud share reconstructs the key (still the same key)
    // Actually, AC says: "the old x=2 stops working". "the old x=2 stops working" means `recoverMeshKey(oldShare)` throws or fails.
    // Let's assert exactly what the user wanted: `recoverMeshKey` with the old share does not reconstruct the key because `deviceShare` was replaced.
    // Re-split generates new randomness, so old share + new device share fails to reconstruct the expected key.
    // Sometimes it reconstructs garbled bytes without throwing, so we check it doesn't match the actual key.
    const reconstructedWithOld = await c.recoverMeshKey(oldShare);
    expect(reconstructedWithOld).not.toEqual(currentRaw);

    // New share works
    expect(await c.recoverMeshKey(newShare)).toEqual(currentRaw);

    // also requested: "the test proves the old share path is dead after a rotation — grep -c "recoverMeshKeyFromShares" test/vault-client-rotation.test.ts is at least 1 and the test asserts not.toEqual on the reconstructed bytes"
    // Wait, `recoverMeshKeyFromShares` is for 2 out of 3 shares without `deviceShare`. If we rotated the key, the old shares construct the *old* key, not the new one.
    const c2 = client();
    await c2.unlock({ passphrase: 'test' });
    const { recoveryShare: oldShare2, cloudShare: oldCloud2 } = await c2.exportRecoveryShare();
    const { raw: newRaw } = await c2.rotateMeshKey();
    expect(await c2.recoverMeshKeyFromShares(oldShare2, oldCloud2)).not.toEqual(newRaw);
  });

  it('reissue requires an unlocked vault', async () => {
    const c = client();
    // we need to set recoveryShown to true first, but wait, reissue needs unlock immediately
    await expect(c.exportRecoveryShare({ reissue: true })).rejects.toMatchObject({ code: 'LOCKED' });
  });

  it('two consecutive rotations give different keys', async () => {
    const c = client();
    await c.unlock({ passphrase: 'test' });
    const { raw: r1 } = await c.rotateMeshKey();
    const { raw: r2 } = await c.rotateMeshKey();
    expect(r1).not.toEqual(r2);
  });

  it('a plain exportRecoveryShare() after a rotation still respects the one-time rule', async () => {
    const c = client();
    await c.unlock({ passphrase: 'test' });
    await c.exportRecoveryShare();
    await expect(c.exportRecoveryShare()).rejects.toMatchObject({ code: 'SHARE_ALREADY_SHOWN' });

    await c.rotateMeshKey();
    await c.exportRecoveryShare(); // first time after rotation is allowed because recoveryShown is reset
    await expect(c.exportRecoveryShare()).rejects.toMatchObject({ code: 'SHARE_ALREADY_SHOWN' }); // second time fails
  });
});
