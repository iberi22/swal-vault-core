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

// subir (si hay SWAL_R2 binding, va a R2 real; si no, memory mesh)
const r2 = new R2StorageClient({ appId, instanceId, r2Binding: env.SWAL_R2 });
await r2.uploadSealedPack(pack);

// leer
const got = await r2.getSealedPack(pack.content_hash);
const plain = await unpackSealedPack(got!, pack.shares.slice(0,2));
```

Path R2: `packs/{appId}/{instanceId}/{entity}/{content_hash}.json`
Shares: 2/3 Shamir GF257 reconstruye DEK. Guarda 1 share en KV, 1 en D1 cifrado, 1 local.

## Reuso
- gara-g: vehicle/fleet/telemetry -> sealed
- hosteler-ia: order/inventoryItem/restaurant -> mismo api
- flota: maintenance/fuelLog/document -> mismo

No acopla a econ-sdk: chain defaults polygon 137 si no hay @swal/econ.
