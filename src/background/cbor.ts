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

export function encodeMapHeader(length: number): number[] {
  if (length < 24) return [0xa0 + length];
  if (length < 256) return [0xb8, length];
  return [0xb9, (length >> 8) & 0xff, length & 0xff];
}

export function encodeTextString(value: string): number[] {
  const bytes = new TextEncoder().encode(value);
  const header =
    bytes.length < 24
      ? [0x60 + bytes.length]
      : bytes.length < 256
        ? [0x78, bytes.length]
        : [0x79, (bytes.length >> 8) & 0xff, bytes.length & 0xff];
  return [...header, ...bytes];
}

export function encodeByteString(bytes: Uint8Array): number[] {
  if (bytes.length < 24) return [0x40 + bytes.length, ...bytes];
  if (bytes.length < 256) return [0x58, bytes.length, ...bytes];
  return [0x59, (bytes.length >> 8) & 0xff, bytes.length & 0xff, ...bytes];
}

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
  if (authDataBytes.length <= 23) {
    parts.push(0x40 + authDataBytes.length);
  } else if (authDataBytes.length <= 255) {
    parts.push(0x58, authDataBytes.length);
  } else {
    parts.push(0x59, (authDataBytes.length >> 8) & 0xff, authDataBytes.length & 0xff);
  }

  const result = new Uint8Array(parts.length + authDataBytes.length);
  result.set(parts, 0);
  result.set(authDataBytes, parts.length);
  return result.buffer;
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
  extensionsData?: Uint8Array | null
): Promise<ArrayBuffer> {
  const rpIdBytes = new TextEncoder().encode(rpId);
  const rpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', rpIdBytes));

  // The extension supplies user presence through its trusted consent UI, but
  // has no user-verification ceremony. Never claim UV to the relying party.
  let flagsByte = includeAttestedCredentialData ? 0x41 : 0x01;
  if (extensionsData && extensionsData.length > 0) flagsByte |= 0x80;
  const flags = new Uint8Array([flagsByte]);

  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, counter, false);

  if (includeAttestedCredentialData && credentialId && publicKeyRaw) {
    const aaguid = PASSKEY_VAULT_AAGUID;
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
