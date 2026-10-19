import { describe, it, expect } from 'vitest';
import {
  createSealedPack,
  verifySealedPackSignature,
  verifySealedPackHash,
  unpackSealedPack,
  migratePackV2ToV3,
  PACK_VERSION
} from '../src/sealedPack.js';
import { toHex, fromHex, bs, utf8, randomBytes, toBase64 } from '../src/bytes.js';

describe('SealedPack signers and pinning', () => {
  const meta = { entity: 'vehicle', timestamp: 123456 };
  const payload = utf8('hello world');

  it('a pack with no signer has no sigAlg and verifies', async () => {
    const pack = await createSealedPack(payload, meta);
    expect(pack.sigAlg).toBeUndefined();
    expect(await verifySealedPackSignature(pack)).toBe(true);
    expect(await verifySealedPackHash(pack)).toBe(true);
  });

  it('a pack signed with a generated ECDSA P-256 key has sigAlg === ECDSA-P256 and verifies', async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const pubSpki = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', pair.publicKey));
    const signer = {
      alg: 'ECDSA-P256' as const,
      publicKey: pubSpki,
      sign: async (data: Uint8Array) => {
        return new Uint8Array(
          await globalThis.crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, bs(data))
        );
      }
    };
    const pack = await createSealedPack(payload, meta, undefined, { signer });
    expect(pack.sigAlg).toBe('ECDSA-P256');
    expect(await verifySealedPackSignature(pack)).toBe(true);
  });

  it('the same pack with one flipped byte in signature does not verify', async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const pubSpki = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', pair.publicKey));
    const signer = {
      alg: 'ECDSA-P256' as const,
      publicKey: pubSpki,
      sign: async (data: Uint8Array) => {
        return new Uint8Array(
          await globalThis.crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, bs(data))
        );
      }
    };
    const pack = await createSealedPack(payload, meta, undefined, { signer });
    const sigBytes = fromHex(pack.signature);
    sigBytes[0] ^= 1;
    pack.signature = toHex(sigBytes);
    expect(await verifySealedPackSignature(pack)).toBe(false);
  });

  it('pinning accepts the right hex key and rejects a different one (ECDSA)', async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const pubSpki = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', pair.publicKey));
    const signer = {
      alg: 'ECDSA-P256' as const,
      publicKey: pubSpki,
      sign: async (data: Uint8Array) => {
        return new Uint8Array(
          await globalThis.crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, bs(data))
        );
      }
    };
    const pack = await createSealedPack(payload, meta, undefined, { signer });
    const rightHex = toHex(pubSpki);
    const wrongHex = toHex(randomBytes(pubSpki.length));
    expect(await verifySealedPackSignature(pack, [rightHex])).toBe(true);
    expect(await verifySealedPackSignature(pack, [wrongHex])).toBe(false);
  });

  it('a pinned check against an Ed25519 pack works too', async () => {
    const pack = await createSealedPack(payload, meta);
    const rightHex = pack.publicKey;
    const wrongHex = toHex(randomBytes(32));
    expect(await verifySealedPackSignature(pack, [rightHex])).toBe(true);
    expect(await verifySealedPackSignature(pack, [wrongHex])).toBe(false);
  });
});

describe('SealedPack migration from v2 to v3', () => {
  const meta = { entity: 'vehicle', timestamp: 123456, foo: 'bar' };
  const payload = utf8('migrate me');

  const createV2Mock = async () => {
    const dek = randomBytes(32);
    const iv = randomBytes(12);
    const key = await globalThis.crypto.subtle.importKey('raw', bs(dek), 'AES-GCM', false, ['encrypt']);
    const sealed = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: bs(iv), tagLength: 128, additionalData: bs(utf8(`swal-vault/v2|{"entity":"vehicle","foo":"bar","timestamp":123456}`)) }, key, bs(payload)));
    const ct = sealed.subarray(0, sealed.length - 16), tag = sealed.subarray(sealed.length - 16);
    const { splitDEK, computeContentHashAsync } = await import('../src/sealedPack.js');
    const shares = splitDEK(dek, 2);
    const content_hash = await computeContentHashAsync(ct, meta);
    const v2pack = {
      v: 2,
      id: 'legacy', content_hash, ciphertext: toBase64(ct), iv: toBase64(iv),
      tag: toBase64(tag), shares, signature: '', publicKey: '', metadata: meta, chain: 'polygon', chainId: 137,
    } as any;
    return v2pack;
  };

  it('migratePackV2ToV3 returns a pack with v === 3 whose payload round-trips through unpackSealedPack', async () => {
    const v2pack = await createV2Mock();
    const migrated = await migratePackV2ToV3(v2pack, v2pack.shares.slice(0, 2));
    expect(migrated.v).toBe(3);
    const recovered = await unpackSealedPack(migrated, migrated.shares.slice(0, 2));
    expect(recovered).toEqual(payload);
  });

  it('the migrated pack has different shares than the input', async () => {
    const v2pack = await createV2Mock();
    const migrated = await migratePackV2ToV3(v2pack, v2pack.shares.slice(0, 2));
    expect(migrated.shares[0].value).not.toBe(v2pack.shares[0].value);
    expect(migrated.shares[1].value).not.toBe(v2pack.shares[1].value);
  });

  it('migration with a wrong pair of shares throws', async () => {
    const v2pack = await createV2Mock();
    const wrongShares = [{ ...v2pack.shares[0], value: 'wrong', v: 2 }, v2pack.shares[1]];
    await expect(migratePackV2ToV3(v2pack, wrongShares)).rejects.toThrow();
  });

  it('the input pack is unchanged after migration (compare content_hash, ciphertext and shares)', async () => {
    const v2pack = await createV2Mock();
    const originalHash = v2pack.content_hash;
    const originalCiphertext = v2pack.ciphertext;
    const originalShares = JSON.parse(JSON.stringify(v2pack.shares));

    await migratePackV2ToV3(v2pack, v2pack.shares.slice(0, 2));

    expect(v2pack.content_hash).toBe(originalHash);
    expect(v2pack.ciphertext).toBe(originalCiphertext);
    expect(v2pack.shares).toEqual(originalShares);
  });

  it('verifySealedPackHash still returns true for the migrated pack', async () => {
    const v2pack = await createV2Mock();
    const migrated = await migratePackV2ToV3(v2pack, v2pack.shares.slice(0, 2));
    expect(await verifySealedPackHash(migrated)).toBe(true);
  });
});
