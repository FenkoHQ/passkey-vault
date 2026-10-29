/**
 * clientDataJSON, serialized exactly as WebAuthn Level 3 §5.8.1.1 specifies.
 *
 * The spec fixes the byte layout, not just the JSON content: type, challenge,
 * origin and crossOrigin always come first and in that order, so verifiers
 * may check the bytes against a template instead of parsing JSON (the
 * "limited verification algorithm", §5.8.1.2). Such a verifier rejects any
 * clientDataJSON that leaves crossOrigin out, as JSON.stringify of a plain
 * object did here.
 */

export interface CollectedClientData {
  type: 'webauthn.create' | 'webauthn.get';
  /** base64url of the relying party's challenge. */
  challenge: string;
  /** Serialized origin of the calling document. */
  origin: string;
  /** The caller is not same-origin with all of its ancestors. */
  crossOrigin: boolean;
  /** Top-level origin, only when crossOrigin is true. */
  topOrigin?: string;
}

/** CCDToString (§5.8.1.1): JSON string escaping with lower-case \u escapes. */
function ccdToString(value: string): string {
  let encoded = '"';
  for (const char of value) {
    const codePoint = char.codePointAt(0)!;
    if (codePoint === 0x22) {
      encoded += '\\"';
    } else if (codePoint === 0x5c) {
      encoded += '\\\\';
    } else if (codePoint < 0x20) {
      encoded += '\\u' + codePoint.toString(16).padStart(4, '0');
    } else {
      encoded += char;
    }
  }
  return encoded + '"';
}

export function serializeClientData(data: CollectedClientData): string {
  if (typeof data.challenge !== 'string' || typeof data.origin !== 'string') {
    throw new TypeError('clientData needs a challenge and an origin');
  }
  let result =
    '{"type":' +
    ccdToString(data.type) +
    ',"challenge":' +
    ccdToString(data.challenge) +
    ',"origin":' +
    ccdToString(data.origin) +
    ',"crossOrigin":' +
    (data.crossOrigin ? 'true' : 'false');
  if (data.crossOrigin && data.topOrigin) {
    result += ',"topOrigin":' + ccdToString(data.topOrigin);
  }
  return result + '}';
}
