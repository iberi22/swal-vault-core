// cloudShare.ts — interfaz agnostica de almacenamiento para el unico share que la nube puede tener (x=3).
// Implementala con D1 (recomendado: 100.000 filas/dia), KV (1 escritura por registro; cupo de 1.000
// escrituras/dia por cuenta de Cloudflare) o memoria en tests. El vault no depende de ninguna.
import { assertCloudSharesSafe, CLOUD_SHARE_INDEX, cloudBoundShare, type DEKShare, type SealedPack } from './sealedPack.js';

export interface CloudShareStore {
  /** Guarda el share x=3 del pack `packId`. */
  put(packId: string, share: DEKShare): Promise<void>;
  get(packId: string): Promise<DEKShare | null>;
  delete(packId: string): Promise<void>;
}

/** Guarda en `store` el unico share permitido (x=3) de un pack recien sellado. Lanza si no existe. */
export async function storeCloudShare(store: CloudShareStore, pack: SealedPack): Promise<void> {
  const share = cloudBoundShare(pack.shares);
  if (!share) throw new Error(`El pack no tiene el share x=${CLOUD_SHARE_INDEX}`);
  assertCloudSharesSafe(1);
  await store.put(pack.id, share);
}

/** Implementacion en memoria (tests / mesh-only). */
export class MemoryCloudShareStore implements CloudShareStore {
  private m = new Map<string, DEKShare>();
  async put(id: string, s: DEKShare) { if (s.index !== CLOUD_SHARE_INDEX) throw new Error('solo se admite el share x=3'); this.m.set(id, { ...s }); }
  async get(id: string) { const s = this.m.get(id); return s ? { ...s } : null; }
  async delete(id: string) { this.m.delete(id); }
}
