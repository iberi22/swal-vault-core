# @swal/vault — Core reusable cifrado 100%

Extraído de `apps/gara-g` a `cores/swal-vault` para reuso en todos los forks (gara-g, hosteler-ia, flota, etc).

## Que resuelve
- 100% cifrado: Cloudflare solo ve ciphertext+shares+hash, nunca plaintext.
- Pay-per-use 5%: si usas R2/D1 pagas infra+AI*1.10+5%, si no usas backend 0$ (mesh P2P replica en otros nodos gara-g).
- 1 camion = 100 camiones mismo precio (no hay fee por vehiculo).

## Uso en cualquier app

```ts
import { createSealedPack, unpackSealedPack, R2StorageClient } from '@swal/vault';

// crear
const payload = new TextEncoder().encode(JSON.stringify({ plate: 'ABC123', km: 50000 }));
const pack = await createSealedPack(payload, { entity:'vehicle', entityId: rec.id, appId, instanceId, timestamp: Date.now() });

// subir: el cliente SOLO acepta packs con <2 shares y sube siempre packWithoutShares.
// Shares 1 (dispositivo) y 2 (recuperacion) NUNCA salen del cliente; solo el x=3 puede ir a la nube.
const r2 = new R2StorageClient({ appId, instanceId, r2Binding: env.SWAL_R2 });
await r2.uploadSealedPack(packWithoutShares(pack));       // pasar el pack completo lanza error E2EE
await storeCloudShare(shareStore, pack);                  // guarda solo x=3 (CloudShareStore: D1 recomendado)

// leer (el pack de R2 no trae shares; combina las que tengas localmente)
const got = await r2.getSealedPack(pack.content_hash);
const plain = await unpackSealedPack(got!, [deviceShare, recoveryShare]);
```

Path R2: `packs/{appId}/{instanceId}/{entity}/{content_hash}.json`
Shares: 2/3 Shamir GF257 reconstruye DEK. x=1 en el dispositivo, x=2 de recuperacion (usuario), x=3 unico share en la nube.
La nube (R2+D1+KV) nunca debe acumular 2 shares.

### Share de nube: D1 mejor que KV
`CloudShareStore` (`put/get/delete`) es una interfaz agnostica; hay `MemoryCloudShareStore` para tests. KV cobra 1 escritura
por registro y la cuenta de Cloudflare tiene **1.000 escrituras KV/dia compartidas por todos los proyectos**; guarda el share x=3 en D1 (100.000 filas/dia).

### Formato y metadatos
`pack.v = 2`: los metadatos se ligan como AAD de AES-GCM (alterarlos, o el tag/ciphertext, rompe el descifrado). Los metadatos viajan en
claro; solo se admiten las claves de `CLEAR_METADATA_KEYS` (o `extraClearKeys` explicito en `createSealedPack`). Los packs sin `v` (legado) se siguen leyendo.
`registerOnPolygon` esta eliminado (lanza `not implemented`): el anclaje real no existe aun.

### Gate local
`.husky/pre-commit` y `pre-push` ejecutan `vitest run` y `tsc --noEmit` (`pnpm install` activa `core.hooksPath`).

## Reuso
- gara-g: vehicle/fleet/telemetry -> sealed
- hosteler-ia: order/inventoryItem/restaurant -> mismo api
- flota: maintenance/fuelLog/document -> mismo

No acopla a econ-sdk: chain defaults polygon 137 si no hay @swal/econ.

## Navegador (PWA) — `@swal/vault/web`

Todo el paquete usa solo WebCrypto (`globalThis.crypto.subtle`, Node >=19 y navegadores) y `Uint8Array`; sin `node:crypto` ni `Buffer`. Firma de packs: Ed25519 (requiere Chrome 137+/Firefox 129+/Safari 17+ o Node). Cambios de API: `computeContentHash` queda deprecado (usa `computeContentHashAsync`); el par de claves de `createSealedPack` es ahora `CryptoKeyPair` (se siguen aceptando `KeyObject` de node); nuevo `verifySealedPackSignature`.

```ts
import { createVaultClient } from '@swal/vault/web';

const vault = createVaultClient({ storage: 'idb', dbName: 'mi-app-vault' });
const id = await vault.getDeviceIdentity();            // ECDSA P-256 no extraible en IndexedDB
await vault.unlockPreferPasskey('mi passphrase');      // passkey PRF si hay; si no PBKDF2-SHA256 (600k)
const { raw, key } = await vault.getOrCreateMeshKey(); // 32 bytes + CryptoKey AES-GCM; en reposo siempre envuelta
const { recoveryShare, cloudShare } = await vault.exportRecoveryShare(); // se muestra UNA vez
```

Nunca hace peticiones de red. Share 1 queda en el dispositivo, share 2 (recuperacion) se entrega al usuario, share 3 es de custodia opcional; con menos de 2 shares no se reconstruye nada. `resetPassphrase(recoveryShare, nueva)` recupera la meshKey si se olvida la passphrase.
