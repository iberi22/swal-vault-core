# @swal/vault

[![CI](https://github.com/iberi22/swal-vault-core/actions/workflows/ci.yml/badge.svg)](https://github.com/iberi22/swal-vault-core/actions/workflows/ci.yml)

Pure WebCrypto end-to-end encrypted (E2EE) storage core with Shamir's Secret Sharing (2-of-3 threshold), AES-256-GCM authenticated encryption with associated data (AEAD), and zero-knowledge cloud synchronization.

Built for privacy-first, local-first web applications and edge runtimes.

---

## Overview

`@swal/vault` provides cryptographic building blocks and local key custody for modern web applications and cloud edge services. It is designed so that backend storage providers (such as Cloudflare R2, D1, or S3-compatible stores) only ever see ciphertext, authentication tags, and public metadata—never plaintext data or sufficient key material to decrypt it.

### Core Properties

- **100% End-to-End Encrypted (E2EE):** Data is encrypted on the client device using an ephemeral Data Encryption Key (DEK).
- **2-of-3 Shamir Secret Sharing:** The DEK is split into three shares over $\text{GF}(257)$. Reconstructing the DEK requires any two shares.
  - **Share 1 ($x=1$):** Kept strictly on the local device.
  - **Share 2 ($x=2$):** Recovery share provided to the user upon onboarding.
  - **Share 3 ($x=3$):** Cloud custody share stored in a database (such as Cloudflare D1).
- **Zero Cloud Compromise:** Because the cloud backend never holds more than one share ($x=3$), the operator or a compromised cloud infrastructure cannot decrypt user records.
- **Pure WebCrypto Runtime:** Relies exclusively on standard `globalThis.crypto.subtle` and `Uint8Array`. Zero dependencies on Node.js-specific modules (`node:crypto`, `Buffer`). Runs seamlessly in browsers (PWAs), Cloudflare Workers, Node.js (>= 19), Bun, and Deno.
- **Tamper-Proof Metadata (AEAD):** In Pack format v2, metadata is authenticated as Additional Authenticated Data (AAD) in AES-GCM. Modifying metadata, ciphertext, IV, or tag causes decryption to fail.
- **Hardware-Backed Identity & Key Wrapping:** Client module (`@swal/vault/web`) provides non-extractable IndexedDB key custody, passkey PRF support, and PBKDF2-SHA256 key derivation with up to 600,000 iterations.

---

## Installation

```bash
npm install @swal/vault
# or
pnpm add @swal/vault
```

---

## Usage Guide

### 1. Sealing and Unpacking Data

```ts
import {
  createSealedPack,
  unpackSealedPack,
  packWithoutShares,
  packMetadataForEntity,
} from '@swal/vault';

// 1. Prepare plaintext payload and metadata
const payload = new TextEncoder().encode(JSON.stringify({ secretNote: 'Confidential message' }));
const metadata = packMetadataForEntity('document', 'doc-123', 'my-app', 'instance-1');

// 2. Create sealed pack (AES-256-GCM + Shamir 2/3 + Ed25519 signature)
const pack = await createSealedPack(payload, metadata);

// pack.shares contains 3 shares:
// - Share 1 (index: 1): store in device IndexedDB
// - Share 2 (index: 2): backup/recovery key for user
// - Share 3 (index: 3): cloud custody share

// 3. Prepare pack for cloud storage (strips shares)
const cloudSafePack = packWithoutShares(pack);

// 4. Decrypt payload using any 2 shares
const deviceShare = pack.shares[0]; // x=1
const recoveryShare = pack.shares[1]; // x=2

const decryptedBytes = await unpackSealedPack(cloudSafePack, [deviceShare, recoveryShare]);
const decryptedText = new TextDecoder().decode(decryptedBytes);
```

### 2. Cloud Storage Boundary (R2 & CloudShareStore)

```ts
import { R2StorageClient, storeCloudShare, MemoryCloudShareStore } from '@swal/vault';

// Initialize R2 storage client (supports real Cloudflare Worker R2 bucket bindings or in-memory fallback)
const r2 = new R2StorageClient({
  appId: 'my-app',
  instanceId: 'inst-01',
  r2Binding: env.SWAL_R2, // Cloudflare R2 bucket binding (optional)
});

// Upload pack: enforce that no more than 1 share is uploaded.
// uploadSealedPack automatically strips shares and throws an error if >= 2 shares are present.
await r2.uploadSealedPack(pack);

// Store the single permitted cloud share (x=3) in CloudShareStore (D1 / KV / Memory)
const shareStore = new MemoryCloudShareStore();
await storeCloudShare(shareStore, pack);

// Retrieve and decrypt
const storedPack = await r2.getSealedPack(pack.content_hash);
const cloudShare = await shareStore.get(pack.id);

if (storedPack && cloudShare) {
  const plain = await unpackSealedPack(storedPack, [deviceShare, cloudShare]);
}
```

### 3. Browser Client (`@swal/vault/web`)

The browser client provides zero-network, local-first key lifecycle management in IndexedDB.

```ts
import { createVaultClient } from '@swal/vault/web';

// 1. Initialize client with IndexedDB backing
const vault = createVaultClient({
  storage: 'idb',
  dbName: 'app-vault-storage',
  pbkdf2Iterations: 600_000, // minimum allowed is 310,000
});

// 2. Hardware / device identity (non-extractable ECDSA P-256)
const identity = await vault.getDeviceIdentity();

// 3. Unlock KEK via Passkey PRF (WebAuthn) or passphrase
await vault.unlockPreferPasskey('user-strong-passphrase');

// 4. Retrieve or generate the mesh encryption key (wrapped at rest in IndexedDB)
const { raw, key } = await vault.getOrCreateMeshKey();

// 5. Export recovery shares (allowed only ONCE; subsequent calls throw SHARE_ALREADY_SHOWN)
const { recoveryShare, cloudShare } = await vault.exportRecoveryShare();

// 6. Emergency recovery / passphrase reset using recovery share
await vault.resetPassphrase(recoveryShare, 'new-strong-passphrase');
```

---

## API Reference

### Core (`@swal/vault`)

#### `createSealedPack(payload, metadata, keyPair?, options?)`
Encrypts `payload` with a freshly generated 32-byte AES-GCM DEK, splits the DEK into 3 Shamir shares, computes a SHA-256 content hash over ciphertext and metadata, signs the hash using Ed25519, and binds metadata into the AES-GCM tag via AAD.
- `payload`: `Uint8Array` of data to encrypt.
- `metadata`: `SealedPackMetadata` object. Keys must be whitelisted unless specified in `options.extraClearKeys`.
- `keyPair`: Optional Ed25519 `CryptoKeyPair` (or Node-compatible `KeyObject` pair). A key pair is generated if omitted.
- `options.extraClearKeys`: Optional array of string keys permitted in plaintext metadata.
- Returns: `Promise<SealedPack>`.

### Signature and Migration Details
ECDSA P-256 signatures are expected in raw `r||s` format (64 bytes), not DER. Note that ECDSA signatures may be malleable (high-s vs low-s).
The `migratePackV2ToV3` helper requires the caller to provide the original pack, which will be verified (integrity and signature, using pinned keys) before migration. The helper requires a fresh signer or key pair to sign the migrated pack, and preserves the original pack's `id` (note that the signature covers only `content_hash`, not `id`, `sigAlg`, `publicKey`, or `v`, so preserving `id` is cosmetic). Only packs with `v === 2` can be migrated.


#### `unpackSealedPack(pack, shares)`
Reconstructs the 32-byte DEK from any two valid `DEKShare` objects, verifies the AAD and authentication tag, and decrypts the ciphertext.
- `pack`: `SealedPack`.
- `shares`: `DEKShare[]` containing at least 2 distinct shares.
- Returns: `Promise<Uint8Array>`.

#### `packWithoutShares(pack)`
Returns a shallow copy of `pack` with `shares: []`. Safe for transmitting to cloud backends.

#### `splitDEK(dek)` / `reconstructDEK(shares)`
Low-level Shamir Secret Sharing implementation over $\text{GF}(257)$ (v2) and $\text{GF}(2^8)$ (v3).
- `splitDEK(dek: Uint8Array, version = 3)`: Returns an array of 3 `DEKShare` objects ($x \in \{1, 2, 3\}$), tagged with `v: version`.
- `reconstructDEK(shares: DEKShare[])`: Takes 2 distinct shares and returns the original 32-byte DEK. It dispatches to the correct field based on `share.v ?? 2`. Note: `v` is part of the share format; a v3 share serialized without `v` reconstructs a wrong key silently.

### Pack versions

| Version | Field | Status |
|---|---|---|
| v2 | $\text{GF}(257)$ | read-only legacy |
| v3 | $\text{GF}(2^8)$ | current |

#### `verifySealedPackHash(pack)`
Asynchronously validates that the pack's `content_hash` matches `SHA-256(ciphertext || sorted(metadata))`. Returns `Promise<boolean>`.

#### `verifySealedPackSignature(pack, pinnedPublicKeys?)`
Verifies the signature over `content_hash` using the embedded `publicKey` and the signature algorithm (`pack.sigAlg ?? 'Ed25519'`, which can also be `'ECDSA-P256'`). Note that verification without `pinnedPublicKeys` proves integrity only (the bytes were not altered in transit), not authorship. If `pinnedPublicKeys` is provided, it fails unless `pack.publicKey` is in the list. Returns `Promise<boolean>`.

#### `R2StorageClient`
Storage client adapter for Cloudflare R2 / S3 storage:
- `uploadSealedPack(pack)`: Verifies integrity, strips shares, and stores pack under `packs/{appId}/{instanceId}/{entity}/{content_hash}.json`. Throws if pack contains $\ge 2$ shares.
- `getSealedPack(keyOrHash)`: Fetches pack from R2 or fallback memory store.
- `deleteSealedPack(keyOrHash)`: Deletes pack from storage.
- `listSealedPacks(prefix?)`: Lists stored pack keys.

#### `CloudShareStore` & `storeCloudShare(store, pack)`
- `CloudShareStore`: Abstract storage interface (`put`, `get`, `delete`) for cloud-persisted shares ($x=3$).
- `storeCloudShare(store, pack)`: Extracts share $x=3$ and persists it. Rejects any operation that would store shares with index $\ne 3$.
- `MemoryCloudShareStore`: In-memory reference implementation for testing and mesh node synchronization.

---

### Web (`@swal/vault/web`)

#### `createVaultClient(options)`
Creates a browser vault manager backed by IndexedDB.
- `options.storage`: Currently `'idb'` is supported.
- `options.dbName`: IndexedDB database name (default: `'swal-vault'`).
- `options.pbkdf2Iterations`: PBKDF2 iterations for passphrase derivation (default: `600_000`, minimum: `310_000`).
- `options.passkey`: Optional WebAuthn PRF provider implementation.

#### `VaultClient` Methods
- `getDeviceIdentity(): Promise<DeviceIdentity>`: Returns device ID and SPKI/JWK public keys.
- `sign(data: Uint8Array): Promise<Uint8Array>`: Signs data with device private key.
- `verify(publicKeyJwk, data, signature): Promise<boolean>`: Verifies device signature.
- `unlock(options): Promise<void>`: Unlocks memory KEK using `{ passphrase: string }` or `{ passkey: true }`.
- `unlockPreferPasskey(passphrase): Promise<'passkey' | 'passphrase'>`: Attempts passkey unlock with automatic passphrase fallback.
- `lock(): void`: Wipes in-memory KEK.
- `isUnlocked(): boolean`: Returns current unlock state.
- `getOrCreateMeshKey(): Promise<MeshKey>`: Returns the active wrapped 32-byte mesh key.
- `exportRecoveryShare(): Promise<{ recoveryShare: DEKShare, cloudShare: DEKShare }>`: Exports recovery and cloud shares. Allowed only once.
- `recoverMeshKey(recoveryShare: DEKShare): Promise<Uint8Array>`: Reconstructs mesh key using device share and recovery share.
- `resetPassphrase(recoveryShare: DEKShare, newPassphrase: string): Promise<void>`: Re-wraps mesh key under a new passphrase.

---

## Security

Please refer to the [SECURITY.md](SECURITY.md) file for supported versions, vulnerability reporting instructions, and response targets.

## Security Notes

1. **Threshold Secrecy:** Shamir secret sharing provides information-theoretic security for the threshold: any single share ($k=1$) reveals zero information about the underlying encryption key in v3 (which uses unbiased $\text{GF}(2^8)$), while v2 used $\text{GF}(257)$ and had a small bias.
2. **Cloud Boundary Invariant:** At no point should any single backend service accumulate 2 or more shares. Cloud storage (R2/S3) must only receive packs stripped of shares (`packWithoutShares`). Cloud databases (such as Cloudflare D1) must only ever store share $x=3$. Both `uploadSealedPack` and `storeCloudShare` enforce this programmatically (`assertCloudSharesSafe`).
3. **AEAD Authentication:** Pack format v2 binds metadata directly into AES-GCM via AAD (`swal-vault/v2|...`). Any alteration to ciphertext, initialization vector, authentication tag, or metadata properties will fail decryption.
4. **Clear Metadata Whitelist:** To prevent accidental data leaks in plaintext metadata fields, `createSealedPack` enforces a strict whitelist (`CLEAR_METADATA_KEYS`: `vehicleId`, `entityId`, `entity`, `appId`, `instanceId`, `timestamp`, `recordCount`, `deviceId`). Custom fields require explicit opt-in via `extraClearKeys`.
5. **Key Derivation Standards:** PBKDF2-SHA256 derivation requires a minimum of 310,000 iterations (OWASP recommendation) and defaults to 600,000 iterations. Initializing `VaultClient` with fewer than 310,000 iterations throws a `VaultError`.
6. **Zero Client Network Leakage:** `createVaultClient` performs zero network requests. All private and secret keys remain securely confined to memory and encrypted IndexedDB storage.

---

## Releasing

To publish a new version of the package, a repository secret named `NPM_TOKEN` must be configured in GitHub Actions. Pushing a tag that begins with `v` (e.g., `v1.0.0`) will automatically trigger the release workflow.

---

## Development & Gate

Run tests and typecheck verification:

```bash
# Run test suite
npx vitest run

# Run TypeScript check
npx tsc --noEmit

# Verify package tarball contents
npm pack --dry-run
```

---

## License

[Apache-2.0](LICENSE) © 2026 SouthWest AI Labs (SWAL)
