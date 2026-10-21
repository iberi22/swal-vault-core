import { EnvelopeError } from './types.js';

/** RFC 8785 JSON Canonicalization. `undefined` object members are omitted. */
export function jcs(v: unknown): string {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean': return v ? 'true' : 'false';
    case 'string': return JSON.stringify(v);
    case 'number':
      if (!Number.isFinite(v)) throw new EnvelopeError('format', 'non-finite number');
      return JSON.stringify(Object.is(v, -0) ? 0 : v);
    case 'object': {
      if (Array.isArray(v)) return '[' + v.map((x) => (x === undefined ? 'null' : jcs(x))).join(',') + ']';
      const o = v as Record<string, unknown>;
      const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort(); // UTF-16 code unit order
      return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(o[k])).join(',') + '}';
    }
    default: throw new EnvelopeError('format', 'unsupported JSON value');
  }
}
