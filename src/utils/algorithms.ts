/** COSE algorithm identifier of ES256, the only key type the vault issues. */
export const ES256 = -7;

/**
 * Whether a credential the vault can make (ES256) satisfies the relying
 * party's pubKeyCredParams. An empty or absent list means the client
 * defaults, ES256 and RS256 (WebAuthn Level 3 §5.1.3 step 10); entries whose
 * type is not "public-key" are skipped (step 11). Otherwise the RP lists what
 * its server can verify, and an ES256 key outside that list is a credential
 * it will reject.
 */
export function acceptsEs256(params: unknown): boolean {
  if (!Array.isArray(params) || params.length === 0) {
    return true;
  }
  return params.some(
    (entry) =>
      !!entry &&
      (entry as { type?: unknown }).type === 'public-key' &&
      Number((entry as { alg?: unknown }).alg) === ES256
  );
}
