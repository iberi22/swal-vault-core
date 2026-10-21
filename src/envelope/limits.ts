import { EnvelopeError } from './types.js';

/** Max serialized envelope size in UTF-8 bytes. */
export const MAX_FILE_BYTES = 16 * 1024 * 1024;
/** Max inflated (uncompressed) payload size; enforced by open() and, symmetrically, by seal(). */
export const MAX_INFLATED = 4 * MAX_FILE_BYTES;
/** Critical header extensions this implementation understands (none yet). */
export const KNOWN_CRIT = new Set<string>();

/** Shared crit check used by seal and open. */
export function checkCrit(crit: unknown): void {
  if (!Array.isArray(crit) || crit.some((c) => typeof c !== 'string')) throw new EnvelopeError('format', 'crit');
  if (crit.some((c) => !KNOWN_CRIT.has(c))) throw new EnvelopeError('unsupported', 'unknown crit entry');
}
