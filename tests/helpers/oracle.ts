/**
 * An independent relying party: @simplewebauthn/server, one of the most used
 * WebAuthn server libraries. The strict verifier in rp-verifier.ts encodes
 * our reading of the spec; this checks that a library written by someone
 * else, and run by real sites, accepts what the vault produces. Both are fed
 * the credential's toJSON() after a JSON round trip, exactly as a page would
 * POST it to its server.
 */
import {
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type VerifiedRegistrationResponse,
} from '@simplewebauthn/server';

// jsdom exposes `crypto` (tests/setup.ts) but not the SubtleCrypto class the
// library feature-detects through.
const g = globalThis as Record<string, unknown>;
if (!g.SubtleCrypto) {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  g.SubtleCrypto = require('crypto').webcrypto.subtle.constructor;
}

export type OracleCredential = NonNullable<
  VerifiedRegistrationResponse['registrationInfo']
>['credential'];

export async function oracleRegistration(
  credential: unknown,
  expected: { challenge: string; origin: string; rpId: string; requireUserVerification?: boolean }
): Promise<OracleCredential> {
  const result = await verifyRegistrationResponse({
    response: JSON.parse(JSON.stringify(credential)),
    expectedChallenge: expected.challenge,
    expectedOrigin: expected.origin,
    expectedRPID: expected.rpId,
    requireUserVerification: expected.requireUserVerification ?? false,
  });
  if (!result.verified || !result.registrationInfo) {
    throw new Error('SimpleWebAuthn rejected the registration');
  }
  return result.registrationInfo.credential;
}

export async function oracleAuthentication(
  assertion: unknown,
  expected: {
    challenge: string;
    origin: string;
    rpId: string;
    credential: OracleCredential;
    requireUserVerification?: boolean;
  }
): Promise<number> {
  const result = await verifyAuthenticationResponse({
    response: JSON.parse(JSON.stringify(assertion)),
    expectedChallenge: expected.challenge,
    expectedOrigin: expected.origin,
    expectedRPID: expected.rpId,
    credential: expected.credential,
    requireUserVerification: expected.requireUserVerification ?? false,
  });
  if (!result.verified) throw new Error('SimpleWebAuthn rejected the assertion');
  return result.authenticationInfo.newCounter;
}
