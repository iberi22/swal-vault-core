// r2Client.ts — core reusable R2 vault (antes gara-g especifico)
// Reusable para cualquier app SWAL: gara-g, hosteler-ia, flota. Pay-per-use + mesh-only fallback.
// Si hay binding SWAL_R2 (Cloudflare), usa R2 real via fetch/Worker. Si no, memoryStore (mesh-only P2P replica).
// Path generico: packs/{appId}/{instanceId}/{entity}/{content_hash}.json
import type { SealedPack, SealedPackMetadata } from './sealedPack.js';
import { verifySealedPackHash } from './sealedPack.js';

export interface R2ClientConfig {
  bucketName?: string;
  endpointUrl?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  // Cloudflare binding real (cuando corre en Worker/Pages)
  r2Binding?: any; // R2Bucket
  appId?: string;
  instanceId?: string;
}

export class R2StorageClient {
  private bucketName: string;
  private endpointUrl: string;
  private r2Binding: any | null;
  private appId: string;
  private instanceId: string;
  private memoryStore: Map<string, SealedPack> = new Map();

  constructor(config: R2ClientConfig = {}) {
    this.bucketName = config.bucketName || `swal-${config.appId || 'app'}-vault`;
    this.endpointUrl = config.endpointUrl || 'https://r2.swal.dev';
    this.r2Binding = config.r2Binding ?? null;
    this.appId = config.appId || 'my-app';
    this.instanceId = config.instanceId || 'default';
  }

  getBucketName(): string { return this.bucketName; }
  isCloudEnabled(): boolean { return !!this.r2Binding; }

  private r2KeyForPack(pack: SealedPack): string {
    const m: any = pack.metadata;
    const app = (m.appId as string) || this.appId;
    const inst = (m.instanceId as string) || this.instanceId;
    const entity = (m.entity as string) || 'generic';
    return `packs/${app}/${inst}/${entity}/${pack.content_hash}.json`;
  }

  async uploadSealedPack(pack: SealedPack): Promise<{ url: string; contentHash: string; key: string }> {
    if (!pack?.content_hash) throw new Error('SealedPack sin content_hash');
    const ok = await verifySealedPackHash(pack);
    if (!ok) throw new Error('SealedPack content_hash mismatch');

    const key = this.r2KeyForPack(pack);

    // Cloud real si hay binding
    if (this.r2Binding?.put) {
      await this.r2Binding.put(key, JSON.stringify(pack), { httpMetadata: { contentType: 'application/json' } });
    }
    // Siempre memory replica (mesh fallback)
    this.memoryStore.set(key, JSON.parse(JSON.stringify(pack)));
    this.memoryStore.set(pack.content_hash, JSON.parse(JSON.stringify(pack)));

    const url = `${this.endpointUrl}/${this.bucketName}/${key}`;
    return { url, contentHash: pack.content_hash, key };
  }

  async getSealedPack(keyOrHash: string): Promise<SealedPack | null> {
    // Intenta R2 real primero
    if (this.r2Binding?.get) {
      try {
        const obj = await this.r2Binding.get(keyOrHash);
        if (obj) return JSON.parse(await obj.text());
        // intenta como hash -> busca key generica
      } catch {}
    }
    const p = this.memoryStore.get(keyOrHash);
    return p ? JSON.parse(JSON.stringify(p)) : null;
  }

  async deleteSealedPack(keyOrHash: string): Promise<boolean> {
    if (this.r2Binding?.delete) try { await this.r2Binding.delete(keyOrHash); } catch {}
    const pack = this.memoryStore.get(keyOrHash);
    if (!pack) return false;
    this.memoryStore.delete(keyOrHash);
    this.memoryStore.delete(pack.content_hash);
    this.memoryStore.delete(this.r2KeyForPack(pack));
    return true;
  }

  async verifyR2PackIntegrity(keyOrHash: string): Promise<boolean> {
    const p = await this.getSealedPack(keyOrHash);
    if (!p) return false;
    return verifySealedPackHash(p);
  }

  async listSealedPacks(prefix?: string): Promise<string[]> {
    if (this.r2Binding?.list) {
      try {
        const listed = await this.r2Binding.list({ prefix: prefix ?? `packs/${this.appId}/` });
        return (listed.objects ?? []).map((o: any) => o.key);
      } catch {}
    }
    const keys = new Set<string>();
    for (const k of this.memoryStore.keys()) if (k.startsWith('packs/')) keys.add(k);
    const pref = prefix ?? `packs/${this.appId}/`;
    return [...keys].filter((k) => k.startsWith(pref));
  }

  // Helper pay-per-use: calcula bytes para metering
  async estimateStoredBytes(): Promise<number> {
    const keys = await this.listSealedPacks();
    let total = 0;
    for (const k of keys) {
      const p = await this.getSealedPack(k);
      if (p) total += JSON.stringify(p).length;
    }
    return total;
  }
}
