/**
 * Run a ceremony through the vault and verify the result twice: with the
 * strict verifier (rp-verifier.ts) and with SimpleWebAuthn (oracle.ts).
 */

import { fromB64url } from './bytes';
import { oracleAuthentication, oracleRegistration, type OracleCredential } from './oracle';
import {
  authenticationJSON,
  creationOptionsFromJSON,
  registrationJSON,
  requestOptionsFromJSON,
} from './options';
import {
  verifyAuthentication,
  verifyRegistration,
  type AuthenticationResult,
  type CredentialRecord,
} from './rp-verifier';

type Json = Record<string, any>;

export interface Registration {
  json: Json;
  credential: any;
  record: CredentialRecord;
  oracle: OracleCredential;
  origin: string;
  rpId: string;
}

export interface Authentication {
  json: Json;
  assertion: any;
  result: AuthenticationResult;
  oracleCounter: number;
}

function pageOrigin(): string {
  return window.location.origin;
}

/** The RP ID a ceremony runs under: rp.id/rpId when given, else the page host. */
function effectiveRpId(explicit: string | undefined): string {
  return explicit || window.location.hostname;
}

export async function register(
  overrides: Json = {},
  options: { mediation?: CredentialMediationRequirement; requireUserVerification?: boolean } = {}
): Promise<Registration> {
  const json = registrationJSON({
    rp: { name: 'Example', id: window.location.hostname },
    ...overrides,
  });
  const credential = await navigator.credentials.create({
    publicKey: creationOptionsFromJSON(json),
    ...(options.mediation && { mediation: options.mediation }),
  });
  const origin = pageOrigin();
  const rpId = effectiveRpId(json.rp?.id);
  const record = await verifyRegistration(credential, {
    challenge: fromB64url(json.challenge),
    origin,
    rpId,
    userId: fromB64url(json.user.id),
    pubKeyCredParams: json.pubKeyCredParams,
    requireUserVerification: options.requireUserVerification,
    extensions: json.extensions,
  });
  const oracle = await oracleRegistration(credential, {
    challenge: json.challenge,
    origin,
    rpId,
    requireUserVerification: options.requireUserVerification,
  });
  return { json, credential, record, oracle, origin, rpId };
}

export async function authenticate(
  registration: Registration,
  overrides: Json = {},
  options: { requireUserVerification?: boolean; strictCounter?: boolean; rpId?: string } = {}
): Promise<Authentication> {
  const rpId = options.rpId ?? registration.rpId;
  const json = authenticationJSON({ rpId, ...overrides });
  const assertion = await navigator.credentials.get({ publicKey: requestOptionsFromJSON(json) });
  const origin = pageOrigin();
  const result = await verifyAuthentication(assertion, {
    challenge: fromB64url(json.challenge),
    origin,
    rpId,
    record: registration.record,
    allowCredentials: (json.allowCredentials || []).map((c: Json) => fromB64url(c.id)),
    requireUserVerification: options.requireUserVerification,
    extensions: json.extensions,
    strictCounter: options.strictCounter,
  });
  const oracleCounter = await oracleAuthentication(assertion, {
    challenge: json.challenge,
    origin,
    rpId,
    credential: registration.oracle,
    requireUserVerification: options.requireUserVerification,
  });
  // Both RPs advance their stored counter, as a real server would.
  registration.record.signCount = result.signCount;
  registration.oracle.counter = oracleCounter;
  return { json, assertion, result, oracleCounter };
}

/** Settle a promise into a value or the error it rejected with. */
export async function outcome<T>(promise: Promise<T>): Promise<{ value?: T; error?: any }> {
  try {
    return { value: await promise };
  } catch (error) {
    return { error };
  }
}
