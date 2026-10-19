import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import {
  PACK_VERSION, createSealedPack, unpackSealedPack, splitDEK, reconstructDEK,
  packWithoutShares, cloudBoundShare, assertCloudSharesSafe
} from '../src/index.js';
import { randomBytes, toBase64, fromHex, utf8, bs, concatBytes, fromBase64 } from '../src/bytes.js';

describe('sealedPack v3 (GF(2^8))', () => {
  it('PACK_VERSION is 3', () => {
    expect(PACK_VERSION).toBe(3);
  });

  it('GF(2^8) split/reconstruct for all three pairs over 200 random 32-byte secrets', () => {
    for (let i = 0; i < 200; i++) {
      const dek = randomBytes(32);
      const s = splitDEK(dek, 3);
      for (const [a, b] of [[0, 1], [0, 2], [1, 2]]) {
        expect(reconstructDEK([s[a], s[b]])).toEqual(dek);
      }
      expect(() => reconstructDEK([s[0]])).toThrow();
      expect(() => reconstructDEK([s[1], s[1]])).toThrow();
    }
  });

  it('wrong-length input still throws', () => {
    expect(() => splitDEK(randomBytes(31), 3)).toThrow('DEK 32 bytes');
    const s = splitDEK(randomBytes(32), 3);
    s[0].value = toBase64(randomBytes(31));
    expect(() => reconstructDEK([s[0], s[1]])).toThrow('share length 32');
  });

  it('a single share is uniformly distributed', () => {
    const dek = randomBytes(32);
    const counts = new Array(256).fill(0);
    const N = 4000;
    for (let i = 0; i < N; i++) {
      const s = splitDEK(dek, 3);
      const val = Buffer.from(s[0].value, 'base64');
      counts[val[0]]++;
    }
    const mean = N / 256;
    for (let i = 0; i < 256; i++) {
      expect(counts[i]).toBeGreaterThan(0);
      expect(counts[i]).toBeLessThanOrEqual(3 * mean);
    }
  });


  it('a v3 pack unpacked with v3 shares returns the original payload', async () => {
    const payload = new Uint8Array([4, 5, 6]);
    const p = await createSealedPack(payload, { timestamp: 1 });
    expect(p.v).toBe(3);
    const dec = await unpackSealedPack(p, p.shares.slice(0, 2));
    expect(dec).toEqual(payload);
  });

  it('a v2 pack cannot be unpacked with v3-split shares', async () => {
    const dek = randomBytes(32);
    const s3 = splitDEK(dek, 3);
    expect(reconstructDEK([{...s3[0], v: 2}, {...s3[1], v: 2}])).not.toEqual(dek);
  });

  it('shares of different versions never unpack to plaintext', async () => {
    const payload = new Uint8Array([7, 8, 9]);
    const p = await createSealedPack(payload, { timestamp: 1 });
    const s2 = splitDEK(randomBytes(32), 2);
    await expect(unpackSealedPack(p, s2.slice(0, 2))).rejects.toBeDefined();
    const mix = [p.shares[0], s2[1]];
    await expect(unpackSealedPack(p, mix)).rejects.toBeDefined();
  });

  it('packWithoutShares, cloudBoundShare and assertCloudSharesSafe behave as before', () => {
    const p: any = { shares: [{ index: 1 }, { index: 3 }] };
    const p2 = packWithoutShares(p);
    expect(p2.shares).toEqual([]);

    const cs = cloudBoundShare(p.shares);
    expect(cs?.index).toBe(3);

    expect(() => assertCloudSharesSafe(2)).toThrow(/E2EE/);
    expect(() => assertCloudSharesSafe(1)).not.toThrow();
  });


  it('deterministic KAT', () => {
    const katHex = '0524436281a0bfdefd1c3b5a7998b7d6f51433527190afceed0c2b4a6988a7c6';
    const s1 = { index: 1, value: 'VlzeoGasjoiGvP6wdqzuqFbc3kBGzC5oJvw+cDYMDgg=', v: 3 };
    const s2 = { index: 2, value: 'o9Ri/VS43XILR6qVZ/AFKqif8nYfKLaZYPcBPteb7kE=', v: 3 };
    const s3 = { index: 3, value: '8Kz/P7O07CRw529/aMRcVAtXH2QodDc/qwcUBIgfR48=', v: 3 };
    const dek = fromHex(katHex);
    expect(reconstructDEK([s1, s2])).toEqual(dek);
    expect(reconstructDEK([s1, s3])).toEqual(dek);
    expect(reconstructDEK([s2, s3])).toEqual(dek);
  });
});


describe('anti-regression tests for v2 and indices', () => {
  it('creates a real pack with v:2 and AAD swal-vault/v2 and opens it', async () => {
    const payload = utf8('hello');
    const dek = randomBytes(32);
    const shares = splitDEK(dek, 2);
    const key = await globalThis.crypto.subtle.importKey('raw', bs(dek), 'AES-GCM', false, ['encrypt']);
    const iv = randomBytes(12);
    const meta = { entity: 'x', timestamp: 1 };

    // Explicit v2 AAD
    const aad = utf8(`swal-vault/v2|{"entity":"x","timestamp":1}`);
    const sealed = new Uint8Array(
      await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: bs(iv), tagLength: 128, additionalData: bs(aad) }, key, bs(payload))
    );
    const ct = sealed.subarray(0, sealed.length - 16);
    const tag = sealed.subarray(sealed.length - 16);

    const p: any = {
      v: 2,
      id: 'legacy-v2',
      content_hash: '0x',
      ciphertext: toBase64(ct),
      iv: toBase64(iv),
      tag: toBase64(tag),
      shares,
      signature: '',
      publicKey: '',
      metadata: meta,
      chain: 'polygon',
      chainId: 137,
    };

    // open it normally via unpackSealedPack
    const dec = await unpackSealedPack(p, [shares[0], shares[1]]);
    expect(dec).toEqual(payload);
  });

  it('reconstructDEK throws when given a v2 and a v3 share', () => {
    const dek = randomBytes(32);
    const s2 = splitDEK(dek, 2);
    const s3 = splitDEK(dek, 3);
    expect(() => reconstructDEK([s2[0], s3[1]])).toThrow(/Share versions do not match/);
  });

  it('index validation rejects 0, 256, -1, 1.5', () => {
    const s1 = { index: 0, value: toBase64(randomBytes(32)), v: 3 };
    const s2 = { index: 2, value: toBase64(randomBytes(32)), v: 3 };
    expect(() => reconstructDEK([s1, s2])).toThrow(/Invalid share index/);

    s1.index = 256;
    expect(() => reconstructDEK([s1, s2])).toThrow(/Invalid share index/);

    s1.index = -1;
    expect(() => reconstructDEK([s1, s2])).toThrow(/Invalid share index/);

    s1.index = 1.5;
    expect(() => reconstructDEK([s1, s2])).toThrow(/Invalid share index/);
  });

  it('untagged shares are reconstructed as v2', () => {
    const dek = randomBytes(32);
    const s2 = splitDEK(dek, 2);
    const untagged0 = { index: s2[0].index, value: s2[0].value };
    const untagged1 = { index: s2[1].index, value: s2[1].value };
    const recon = reconstructDEK([untagged0, untagged1]);
    expect(recon).toEqual(dek);
  });
});
