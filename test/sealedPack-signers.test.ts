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

  it('createSealedPack throws if the signer generates an invalid signature', async () => {
    const kp = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as any;
    const pubSpki = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', kp.publicKey));
    const badSigner = {
      alg: 'Ed25519' as const,
      publicKey: pubSpki,
      sign: async () => new Uint8Array(64) // 64 zero bytes
    };
    await expect(createSealedPack(payload, meta, undefined, { signer: badSigner })).rejects.toThrow('Generacion de firma invalida');
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
    const { splitDEK, computeContentHashAsync, verifySealedPackSignature } = await import('../src/sealedPack.js');
    const shares = splitDEK(dek, 2);
    const content_hash = await computeContentHashAsync(ct, meta);

    // Generar firma valida Ed25519
    const pair = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as CryptoKeyPair;
    const pubSpki = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', pair.publicKey));
    const sig = new Uint8Array(await globalThis.crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, bs(utf8(content_hash))));

    const v2pack = {
      v: 2,
      id: 'legacy', content_hash, ciphertext: toBase64(ct), iv: toBase64(iv),
      tag: toBase64(tag), shares, signature: toHex(sig), publicKey: toHex(pubSpki), metadata: meta, chain: 'polygon', chainId: 137,
    } as any;
    return v2pack;
  };

  it('migratePackV2ToV3 returns a pack with v === 3 whose payload round-trips through unpackSealedPack', async () => {
    const v2pack = await createV2Mock();
    const migrated = await migratePackV2ToV3(v2pack, v2pack.shares.slice(0, 2), await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as any);
    expect(migrated.v).toBe(3);
    const recovered = await unpackSealedPack(migrated, migrated.shares.slice(0, 2));
    expect(recovered).toEqual(payload);
  });

  it('the migrated pack has different shares than the input', async () => {
    const v2pack = await createV2Mock();
    const migrated = await migratePackV2ToV3(v2pack, v2pack.shares.slice(0, 2), await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as any);
    expect(migrated.shares[0].value).not.toBe(v2pack.shares[0].value);
    expect(migrated.shares[1].value).not.toBe(v2pack.shares[1].value);
  });

  it('migration with a wrong pair of shares throws', async () => {
    const v2pack = await createV2Mock();
    const wrongShares = [{ ...v2pack.shares[0], value: 'wrong', v: 2 }, v2pack.shares[1]];
    await expect(migratePackV2ToV3(v2pack, wrongShares, await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as any)).rejects.toThrow();
  });

  it('the input pack is unchanged after migration (compare content_hash, ciphertext and shares)', async () => {
    const v2pack = await createV2Mock();
    const originalHash = v2pack.content_hash;
    const originalCiphertext = v2pack.ciphertext;
    const originalShares = JSON.parse(JSON.stringify(v2pack.shares));

    await migratePackV2ToV3(v2pack, v2pack.shares.slice(0, 2), await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as any);

    expect(v2pack.content_hash).toBe(originalHash);
    expect(v2pack.ciphertext).toBe(originalCiphertext);
    expect(v2pack.shares).toEqual(originalShares);
  });

  it('verifySealedPackHash still returns true for the migrated pack', async () => {
    const v2pack = await createV2Mock();
    const migrated = await migratePackV2ToV3(v2pack, v2pack.shares.slice(0, 2), await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as any);
    expect(await verifySealedPackHash(migrated)).toBe(true);
  });

  it('migratePackV2ToV3 throws if original pack hash or signature is invalid', async () => {
    const v2pack = await createV2Mock();
    const kp = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as any;

    // Tamper hash
    const badHashPack = { ...v2pack, content_hash: '0x' + toHex(randomBytes(32)) };
    await expect(migratePackV2ToV3(badHashPack, v2pack.shares.slice(0, 2), kp)).rejects.toThrow('Pack hash invalido');

    // Tamper signature
    const badSigPack = { ...v2pack, signature: toHex(randomBytes(64)) };
    await expect(migratePackV2ToV3(badSigPack, v2pack.shares.slice(0, 2), kp)).rejects.toThrow('Pack signature invalida');
  });

  it('migratePackV2ToV3 correctly applies the provided signer, resulting in a defined sigAlg', async () => {
    const v2pack = await createV2Mock();
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

    const migrated = await migratePackV2ToV3(v2pack, v2pack.shares.slice(0, 2), signer);
    expect(migrated.sigAlg).toBe('ECDSA-P256');
    expect(await verifySealedPackSignature(migrated)).toBe(true);
  });

  it('migratePackV2ToV3 preserves the original id', async () => {
    const v2pack = await createV2Mock();
    v2pack.id = 'my-custom-id-123';
    const kp = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as any;
    const migrated = await migratePackV2ToV3(v2pack, v2pack.shares.slice(0, 2), kp);
    expect(migrated.id).toBe('my-custom-id-123');
  });

  it('migratePackV2ToV3 rejects packs with v !== 2', async () => {
    const v2pack = await createV2Mock();
    v2pack.v = 3;
    const kp = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as any;
    await expect(migratePackV2ToV3(v2pack, v2pack.shares.slice(0, 2), kp)).rejects.toThrow('solo acepta packs v2');
  });

  it('verifySealedPackSignature returns false for unknown sigAlg values', async () => {
    const v2pack = await createV2Mock();
    for (const bad of ['none', 'RSA', '', 'ed25519']) {
      const p = { ...v2pack, sigAlg: bad as any };
      expect(await verifySealedPackSignature(p)).toBe(false);
    }
  });

  it('migration does not drop metadata', async () => {
    const v2pack = await createV2Mock();
    const kp = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as any;
    const migrated = await migratePackV2ToV3(v2pack, v2pack.shares.slice(0, 2), kp);
    expect(migrated.metadata).toEqual(v2pack.metadata);
  });
});
