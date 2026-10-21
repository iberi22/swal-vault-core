export type EnvelopeErrorCode = 'format' | 'unsupported' | 'too-large' | 'key' | 'tampered' | 'signature' | 'replay';

export class EnvelopeError extends Error {
  readonly code: EnvelopeErrorCode;
  constructor(code: EnvelopeErrorCode, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.name = 'EnvelopeError';
    this.code = code;
  }
}

export interface PwRecipient { t: 'pw'; kdf: 'PBKDF2-SHA256'; i: number; salt: string; iv: string; wk: string }
export interface CodeRecipient { t: 'code'; salt: string; iv: string; wk: string }
export interface GrpRecipient { t: 'grp'; kid: string; epoch: number; salt: string; iv: string; wk: string }
/** Extension recipient (e.g. `kem`); shape is owned by the provider. */
export interface OtherRecipient { t: string; [k: string]: unknown }
export type Recipient = PwRecipient | CodeRecipient | GrpRecipient | OtherRecipient;

/** Signature block; fields beyond alg/kid are owned by the SignatureProvider. */
export interface SigBlock { alg: string; kid: string; pub?: string; v: string; [k: string]: unknown }

export interface Envelope {
  fmt: 'swal-env/1';
  app: string;
  ns: string;
  schema: string;
  created: string;
  seq?: number;
  crit?: string[];
  aead: 'A256GCM';
  iv: string;
  z?: 'gzip';
  rcpt: Recipient[];
  ct: string;
  sig?: SigBlock;
  [k: string]: unknown;
}

// ---- Seal specs ----
/** `fixed`/`salt`/`iv` overrides exist for deterministic test vectors only. */
export interface PwSpec { t: 'pw'; passphrase: string; iterations?: number; salt?: Uint8Array; iv?: Uint8Array }
export interface CodeSpec { t: 'code'; secret: Uint8Array; salt?: Uint8Array; iv?: Uint8Array }
export interface GrpSpec { t: 'grp'; groupKey: Uint8Array; epoch: number; salt?: Uint8Array; iv?: Uint8Array }
export type RecipientSpec = PwSpec | CodeSpec | GrpSpec;

// ---- Extension hooks (implemented by src/envelope/pq.ts, no edits to core needed) ----
export interface KemWrapContext {
  /** The 32-byte CEK to wrap. */
  cek: Uint8Array;
  /** Wrap AAD bytes: 'swal-env/1|wrap|kem|' + JCS({fmt,app,ns,schema,created,seq}). */
  wrapAad: Uint8Array;
  ns: string;
}
export interface KemUnwrapContext { wrapAad: Uint8Array; ns: string }
export interface KemRecipientProvider {
  t: 'kem';
  /** Returns one or more complete `t:'kem'` recipient entries wrapping the CEK. */
  wrap(ctx: KemWrapContext): Promise<Array<{ t: 'kem'; [k: string]: unknown }>>;
  /** Returns the CEK, or null if this recipient is not addressed to this provider / cannot be opened. */
  unwrap(rcpt: OtherRecipient, ctx: KemUnwrapContext): Promise<Uint8Array | null>;
}
export interface SignatureProvider {
  /** `input` = 'swal-env/1|sig|' || JCS(header) || SHA-256(ct_bytes). */
  sign(input: Uint8Array): Promise<SigBlock>;
  verify(sig: SigBlock, input: Uint8Array): Promise<boolean>;
}

export interface SealOptions {
  app: string;
  ns: string;
  schema: string;
  payload: Uint8Array;
  recipients: RecipientSpec[];
  seq?: number;
  crit?: string[];
  compress?: 'gzip';
  created?: string;
  kem?: KemRecipientProvider;
  signer?: SignatureProvider;
  /** Test-only deterministic CEK / payload IV. */
  fixed?: { cek?: Uint8Array; iv?: Uint8Array };
}

export interface OpenOptions {
  passphrase?: string;
  /** 16-byte machine code secret. */
  code?: Uint8Array;
  /** Candidate group keys; matched by `kid`. */
  groupKeys?: Uint8Array[];
  kem?: KemRecipientProvider;
  verifier?: SignatureProvider;
  requireSignature?: boolean;
  /** Reject (`replay`) when seq <= this value. */
  seqHighWater?: number;
}

export interface OpenResult {
  payload: Uint8Array;
  header: Omit<Envelope, 'ct' | 'sig'>;
  /** Recipient type that opened the envelope. */
  via: string;
  signed: boolean;
  signatureVerified: boolean;
}
