/**
 * Minimal CBOR encoding for WebAuthn authenticator data.
 * Covers map headers, text strings, byte strings, and COSE public keys.
 */

// Fenko Vault AAGUID — d2717a32-9851-48a8-9961-b264c97a411a (random UUIDv4).
// Stable authenticator-model identifier, byte-identical across web/Android/iOS,
// reported so RPs display the "Fenko Vault" brand and icon via the
// passkey-authenticator-aaguids registry. Intentionally non-zero under `none`
// attestation. Canonical reference + registry submission: docs/aaguid/README.md.
export const PASSKEY_VAULT_AAGUID = new Uint8Array([
  0xd2, 0x71, 0x7a, 0x32, 0x98, 0x51, 0x48, 0xa8, 0x99, 0x61, 0xb2, 0x64, 0xc9, 0x7a, 0x41, 0x1a,
]);

const MAJOR_BYTES = 2;
const MAJOR_TEXT = 3;
const MAJOR_MAP = 5;

/**
 * The initial bytes of a CBOR item (RFC 8949 §3): major type plus its
 * argument (a length or count) in the shortest form, as CTAP2's canonical
 * encoding requires. Lengths of 64 KiB and more take the four-byte form.
 */
function encodeHead(majorType: number, argument: number): number[] {
  const major = majorType << 5;
  if (argument < 24) return [major | argument];
  if (argument < 0x100) return [major | 24, argument];
  if (argument < 0x10000) return [major | 25, argument >> 8, argument & 0xff];
  if (argument <= 0xffffffff) {
    return [
      major | 26,
      (argument >>> 24) & 0xff,
      (argument >>> 16) & 0xff,
      (argument >>> 8) & 0xff,
      argument & 0xff,
    ];
  }
  throw new RangeError('CBOR item too large');
}

export function encodeMapHeader(length: number): number[] {
  return encodeHead(MAJOR_MAP, length);
}

export function encodeTextString(value: string): number[] {
  const bytes = new TextEncoder().encode(value);
  return [...encodeHead(MAJOR_TEXT, bytes.length), ...bytes];
}

export function encodeByteString(bytes: Uint8Array): number[] {
  return [...encodeHead(MAJOR_BYTES, bytes.length), ...bytes];
}

/** COSE algorithm identifier for ES256 (RFC 9053), the only key type the vault issues. */
export const COSE_ALG_ES256 = -7;

/**
 * Encode a raw P-256 public key (65 bytes, uncompressed) into COSE Key format.
 */
export function rawPublicKeyToCose(rawKey: ArrayBuffer): Uint8Array {
  const raw = new Uint8Array(rawKey);
  const x = raw.slice(1, 33);
  const y = raw.slice(33, 65);

  const coseKey: number[] = [];
  coseKey.push(0xa5); // map(5)
  coseKey.push(0x01, 0x02); // kty: EC2
  coseKey.push(0x03, 0x26); // alg: ES256
  coseKey.push(0x20, 0x01); // crv: P-256
  coseKey.push(0x21, 0x58, 0x20); // x: bytes(32)
  for (let i = 0; i < x.length; i++) coseKey.push(x[i]);
  coseKey.push(0x22, 0x58, 0x20); // y: bytes(32)
  for (let i = 0; i < y.length; i++) coseKey.push(y[i]);

  return new Uint8Array(coseKey);
}

/**
 * Build a "none" attestation object wrapping authenticator data.
 */
export function createAttestationObjectNone(authenticatorData: ArrayBuffer): ArrayBuffer {
  const authDataBytes = new Uint8Array(authenticatorData);
  const parts: number[] = [];

  // map(3)
  parts.push(0xa3);
  // "fmt"
  parts.push(0x63);
  parts.push(0x66, 0x6d, 0x74);
  // "none"
  parts.push(0x64);
  parts.push(0x6e, 0x6f, 0x6e, 0x65);
  // "attStmt"
  parts.push(0x67);
  parts.push(0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74);
  // {} (empty map)
  parts.push(0xa0);
  // "authData"
  parts.push(0x68);
  parts.push(0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61);

  // byte string header for authData
  parts.push(...encodeHead(MAJOR_BYTES, authDataBytes.length));

  const result = new Uint8Array(parts.length + authDataBytes.length);
  result.set(parts, 0);
  result.set(authDataBytes, parts.length);
  return result.buffer;
}

/** Authenticator data flag bits (WebAuthn L3 §6.1). */
export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;
export const FLAG_AT = 0x40;
export const FLAG_ED = 0x80;

/** All-zero AAGUID — the credential does not identify its authenticator model. */
export const ANONYMOUS_AAGUID = new Uint8Array(16);

/**
 * What the authenticator claims about a ceremony. Defaults reproduce the
 * behaviour these values had while they were constants; the Advanced settings
 * page overrides them per vault (src/background/webauthn-settings.ts).
 */
export interface AuthenticatorDataOptions {
  /** UV — user verification happened. Asserted without a ceremony; see issue #5. */
  userVerified?: boolean;
  /** BE — the credential is eligible for backup / sync. */
  backupEligible?: boolean;
  /** BS — the credential is currently backed up. Ignored unless BE is set. */
  backupState?: boolean;
  /** Authenticator model identifier written into attested credential data. */
  aaguid?: Uint8Array;
}

/**
 * Build authenticator data for create or get operations.
 */
export async function createAuthenticatorData(
  rpId: string,
  credentialId: Uint8Array | null,
  publicKeyRaw: ArrayBuffer | null,
  includeAttestedCredentialData: boolean,
  counter: number = 0,
  extensionsData?: Uint8Array | null,
  options: AuthenticatorDataOptions = {}
): Promise<ArrayBuffer> {
  const rpIdBytes = new TextEncoder().encode(rpId);
  const rpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', rpIdBytes));

  // UP is always set: nothing reaches here without the user clicking through
  // the consent card.
  //
  // UV defaults to set, which is a claim the extension cannot back up — a
  // click is presence, not verification. 0.9.5 cleared it unconditionally and
  // that locked users out: Google (and every other RP requiring user
  // verification) treats a UV=0 assertion as a second-factor-only key and
  // demands a password. It stays on by default until there is a real ceremony
  // to derive it from — see issue #5 — and the user can turn it off.
  let flagsByte = FLAG_UP;
  if (options.userVerified !== false) flagsByte |= FLAG_UV;
  if (options.backupEligible) {
    flagsByte |= FLAG_BE;
    if (options.backupState) flagsByte |= FLAG_BS;
  }
  if (includeAttestedCredentialData) flagsByte |= FLAG_AT;
  if (extensionsData && extensionsData.length > 0) flagsByte |= FLAG_ED;
  const flags = new Uint8Array([flagsByte]);

  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, counter, false);

  if (includeAttestedCredentialData && credentialId && publicKeyRaw) {
    const aaguid = options.aaguid ?? PASSKEY_VAULT_AAGUID;
    const credentialIdLength = new Uint8Array(2);
    new DataView(credentialIdLength.buffer).setUint16(0, credentialId.length, false);
    const cosePublicKey = rawPublicKeyToCose(publicKeyRaw);

    const authData = new Uint8Array(
      rpIdHash.length +
        flags.length +
        counterBytes.length +
        aaguid.length +
        credentialIdLength.length +
        credentialId.length +
        cosePublicKey.length +
        (extensionsData?.length || 0)
    );

    let offset = 0;
    authData.set(rpIdHash, offset);
    offset += rpIdHash.length;
    authData.set(flags, offset);
    offset += flags.length;
    authData.set(counterBytes, offset);
    offset += counterBytes.length;
    authData.set(aaguid, offset);
    offset += aaguid.length;
    authData.set(credentialIdLength, offset);
    offset += credentialIdLength.length;
    authData.set(credentialId, offset);
    offset += credentialId.length;
    authData.set(cosePublicKey, offset);
    offset += cosePublicKey.length;
    if (extensionsData && extensionsData.length > 0) authData.set(extensionsData, offset);

    return authData.buffer;
  } else {
    const authData = new Uint8Array(
      rpIdHash.length + flags.length + counterBytes.length + (extensionsData?.length || 0)
    );
    let offset = 0;
    authData.set(rpIdHash, offset);
    offset += rpIdHash.length;
    authData.set(flags, offset);
    offset += flags.length;
    authData.set(counterBytes, offset);
    offset += counterBytes.length;
    if (extensionsData && extensionsData.length > 0) authData.set(extensionsData, offset);

    return authData.buffer;
  }
}

/**
 * Convert P1363 signature format (r || s, 64 bytes) to DER encoding.
 */
export function convertP1363ToDER(p1363Sig: ArrayBuffer): ArrayBuffer {
  const sig = new Uint8Array(p1363Sig);
  const r = sig.slice(0, 32);
  const s = sig.slice(32, 64);
  const rDer = encodeDERInteger(r);
  const sDer = encodeDERInteger(s);
  const sequenceLength = rDer.length + sDer.length;

  let result;
  if (sequenceLength <= 127) {
    result = new Uint8Array(2 + sequenceLength);
    result[0] = 0x30;
    result[1] = sequenceLength;
    result.set(rDer, 2);
    result.set(sDer, 2 + rDer.length);
  } else {
    result = new Uint8Array(3 + sequenceLength);
    result[0] = 0x30;
    result[1] = 0x81;
    result[2] = sequenceLength;
    result.set(rDer, 3);
    result.set(sDer, 3 + rDer.length);
  }
  return result.buffer;
}

function encodeDERInteger(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  const trimmed = bytes.slice(start);
  const needsPadding = (trimmed[0] & 0x80) !== 0;
  const length = trimmed.length + (needsPadding ? 1 : 0);

  const result = new Uint8Array(2 + length);
  result[0] = 0x02;
  result[1] = length;
  if (needsPadding) {
    result[2] = 0x00;
    result.set(trimmed, 3);
  } else {
    result.set(trimmed, 2);
  }
  return result;
}
