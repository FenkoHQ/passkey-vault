/**
 * The key derivation that new vault keys and new backups use. Stored KDF
 * records weaker than this are upgraded on the next unlock (see
 * SecureStorage.initialize), so raising a parameter here raises it for every
 * vault the next time its owner types the PIN.
 *
 * scrypt N=2^17, r=8, p=1 is the OWASP password storage recommendation. It
 * needs 128 MiB and, in the pure-JS implementation the extension and the
 * mobile apps share, about 0.3 s on a fast 2025 laptop core.
 *
 * Kept in a module of its own so the Jest suite can swap in a cheap profile
 * (tests/setup.ts) without any test switch in the production code path.
 */
export const DEFAULT_KDF = {
  kdf: 'scrypt',
  params: { N: 2 ** 17, r: 8, p: 1 },
} as const;
