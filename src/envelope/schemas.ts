/** Schema registry: ids only. Each app owns validation of its own payload. */
export const SCHEMA_IDS = [
  'swal-inventory-export@1',
  'gara-g-local-dump@1',
  'swal-backup@1',
  'health-export@1',
  'yjs-update@1',
] as const;
export type SchemaId = (typeof SCHEMA_IDS)[number];
export function isKnownSchema(id: string): id is SchemaId {
  return (SCHEMA_IDS as readonly string[]).includes(id);
}
