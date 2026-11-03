/**
 * A strict WebAuthn Relying Party, for checking what the vault returns.
 *
 * Implements the registration and authentication ceremonies of WebAuthn
 * Level 3 (W3C Recommendation, §7.1 and §7.2) and adds the checks a picky
 * real-world verifier makes on top:
 *
 *   - clientDataJSON in the exact §5.8.1.1 serialization, so verifiers using
 *     the §5.8.1.2 limited verification algorithm (a byte-prefix match)
 *     accept it, not just full JSON parsers
 *   - attestation object, COSE key and extensions in CTAP2 canonical CBOR
 *   - authenticator data with no trailing bytes and RFU flag bits clear
 *   - signatures in strict DER (minimal INTEGERs, short-form lengths)
 *   - the Level 3 convenience methods agreeing with the attestation object
 *   - toJSON() output matching the binary fields
 *
 * Every problem is collected, so one failing ceremony reports all of them.
 */

import { decodeCbor, type CborValue } from './cbor-strict';
import {
  b64url,
  bs,
  concat,
  equalBytes,
  fromB64url,
  isArrayBuffer,
  isB64url,
  sha256,
  toBytes,
} from './bytes';

export const FLAG_UP = 0x01;
export const FLAG_RFU1 = 0x02;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;
export const FLAG_RFU2 = 0x20;
export const FLAG_AT = 0x40;
export const FLAG_ED = 0x80;

const COSE_KTY = 1;
const COSE_ALG = 3;
const COSE_CRV = -1;
const COSE_X = -2;
const COSE_Y = -3;
const COSE_KTY_EC2 = 2;
const COSE_CRV_P256 = 1;
const ES256 = -7;

/** Order of the P-256 group, for signature range checks. */
const P256_N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

export class ConformanceError extends Error {
  constructor(readonly issues: string[]) {
    super(`WebAuthn conformance failures:\n  - ${issues.join('\n  - ')}`);
    this.name = 'ConformanceError';
  }
}

export interface ParsedAuthenticatorData {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  aaguid?: Uint8Array;
  credentialId?: Uint8Array;
  credentialPublicKey?: Map<CborValue, CborValue>;
  credentialPublicKeyBytes?: Uint8Array;
  extensions?: Map<CborValue, CborValue>;
}

export interface CredentialRecord {
  id: string;
  rawId: Uint8Array;
  publicKey: CryptoKey;
  publicKeyCose: Uint8Array;
  signCount: number;
  uvInitialized: boolean;
  transports: string[];
  backupEligible: boolean;
  backupState: boolean;
  aaguid: Uint8Array;
  /** user.id from the creation options, the handle sign-in must return. */
  userHandle: Uint8Array;
  rpId: string;
}

export interface ClientDataExpectation {
  type: 'webauthn.create' | 'webauthn.get';
  challenge: Uint8Array;
  origin: string;
  /** The ceremony ran in an iframe that is not same-origin with its ancestors. */
  crossOrigin?: boolean;
  /** The top-level origin when the ceremony ran in a cross-origin iframe. */
  topOrigin?: string;
}

export interface RegistrationExpectation {
  challenge: Uint8Array;
  origin: string;
  rpId: string;
  userId: Uint8Array;
  pubKeyCredParams?: Array<{ type: string; alg: number | string }>;
  requireUserVerification?: boolean;
  crossOrigin?: boolean;
  topOrigin?: string;
  extensions?: Record<string, unknown>;
}

export interface AuthenticationExpectation {
  challenge: Uint8Array;
  origin: string;
  rpId: string;
  record: CredentialRecord;
  allowCredentials?: Uint8Array[];
  requireUserVerification?: boolean;
  crossOrigin?: boolean;
  topOrigin?: string;
  extensions?: Record<string, unknown>;
  /** Fail on a counter that did not move forward (default true). */
  strictCounter?: boolean;
}

/** CCDToString from §5.8.1.1. */
export function ccdToString(value: string): string {
  let out = '"';
  for (const char of value) {
    const cp = char.codePointAt(0)!;
    if (cp === 0x22) out += '\\"';
    else if (cp === 0x5c) out += '\\\\';
    else if (cp === 0x20 || cp === 0x21 || (cp >= 0x23 && cp <= 0x5b) || cp >= 0x5d) out += char;
    else out += '\\u' + cp.toString(16).padStart(4, '0');
  }
  return out + '"';
}

/** The §5.8.1.2 limited verification algorithm: true when the bytes match. */
export function limitedVerifyClientData(
  clientDataJSON: Uint8Array,
  expected: ClientDataExpectation,
  requireTopOrigin = false
): boolean {
  const text = new TextDecoder().decode(clientDataJSON);
  let prefix =
    '{"type":' +
    ccdToString(expected.type) +
    ',"challenge":' +
    ccdToString(b64url(expected.challenge)) +
    ',"origin":' +
    ccdToString(expected.origin) +
    ',"crossOrigin":';
  if (expected.topOrigin !== undefined) {
    prefix += 'true';
    if (requireTopOrigin || text.startsWith(',"topOrigin":', prefix.length)) {
      prefix += ',"topOrigin":' + ccdToString(expected.topOrigin);
    }
  } else {
    prefix += 'false';
  }
  if (!text.startsWith(prefix) || text.length <= prefix.length) return false;
  return text[prefix.length] === '}' || text[prefix.length] === ',';
}

function checkClientData(
  bytes: Uint8Array,
  expected: ClientDataExpectation,
  issues: string[]
): void {
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    issues.push('clientDataJSON starts with a byte order mark');
  }
  let c: Record<string, unknown>;
  try {
    c = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (error) {
    issues.push(`clientDataJSON is not UTF-8 JSON: ${(error as Error).message}`);
    return;
  }
  if (c.type !== expected.type)
    issues.push(`clientData.type is ${c.type}, expected ${expected.type}`);
  if (c.challenge !== b64url(expected.challenge)) {
    issues.push(`clientData.challenge ${c.challenge} is not base64url of the RP's challenge`);
  }
  if (c.origin !== expected.origin)
    issues.push(`clientData.origin ${c.origin} != ${expected.origin}`);
  const crossOrigin = expected.crossOrigin ?? expected.topOrigin !== undefined;
  if (!crossOrigin) {
    if (c.crossOrigin === true)
      issues.push('clientData.crossOrigin is true for a same-origin call');
    if ('topOrigin' in c) issues.push('clientData.topOrigin present for a same-origin call');
  } else {
    if (c.crossOrigin !== true)
      issues.push('clientData.crossOrigin should be true in a cross-origin iframe');
    if (expected.topOrigin !== undefined && c.topOrigin !== expected.topOrigin) {
      issues.push(`clientData.topOrigin ${c.topOrigin} != ${expected.topOrigin}`);
    }
  }
  if (!('crossOrigin' in c)) {
    issues.push('clientData.crossOrigin is missing (the §5.8.1.1 serialization always writes it)');
  }
  if ('tokenBinding' in c) issues.push('clientData.tokenBinding is reserved and must not be sent');
  // The limited algorithm can only express crossOrigin:true alongside a topOrigin.
  const limitedApplies = !crossOrigin || expected.topOrigin !== undefined;
  if (limitedApplies && !limitedVerifyClientData(bytes, expected)) {
    issues.push(
      'clientDataJSON fails the §5.8.1.2 limited verification algorithm: ' +
        new TextDecoder().decode(bytes).slice(0, 200)
    );
  }
}

export function parseAuthenticatorData(
  bytes: Uint8Array,
  issues: string[]
): ParsedAuthenticatorData | null {
  if (bytes.length < 37) {
    issues.push(`authenticator data is ${bytes.length} bytes, shorter than 37`);
    return null;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const parsed: ParsedAuthenticatorData = {
    rpIdHash: bytes.slice(0, 32),
    flags: bytes[32],
    signCount: view.getUint32(33),
  };
  if (parsed.flags & (FLAG_RFU1 | FLAG_RFU2)) {
    issues.push(`reserved flag bits set: 0x${parsed.flags.toString(16)}`);
  }
  let pos = 37;
  if (parsed.flags & FLAG_AT) {
    if (bytes.length < pos + 18) {
      issues.push('AT flag set but attested credential data is truncated');
      return parsed;
    }
    parsed.aaguid = bytes.slice(pos, pos + 16);
    const idLength = view.getUint16(pos + 16);
    pos += 18;
    if (idLength > 1023) issues.push(`credential ID length ${idLength} exceeds 1023`);
    if (idLength < 16)
      issues.push(`credential ID length ${idLength} is under the 16 bytes of entropy RPs assume`);
    parsed.credentialId = bytes.slice(pos, pos + idLength);
    pos += idLength;
    try {
      const { value, end } = decodeCbor(bytes.subarray(pos), { allowTrailing: true });
      if (!(value instanceof Map)) issues.push('credentialPublicKey is not a CBOR map');
      else parsed.credentialPublicKey = value;
      parsed.credentialPublicKeyBytes = bytes.slice(pos, pos + end);
      pos += end;
    } catch (error) {
      issues.push(`credentialPublicKey: ${(error as Error).message}`);
      return parsed;
    }
  }
  if (parsed.flags & FLAG_ED) {
    try {
      const { value, end } = decodeCbor(bytes.subarray(pos), { allowTrailing: true });
      if (!(value instanceof Map)) issues.push('extensions are not a CBOR map');
      else parsed.extensions = value;
      pos += end;
    } catch (error) {
      issues.push(`authenticator extensions: ${(error as Error).message}`);
      return parsed;
    }
  }
  if (pos !== bytes.length)
    issues.push(`${bytes.length - pos} trailing bytes after authenticator data`);
  return parsed;
}

async function importCoseKey(
  cose: Map<CborValue, CborValue>,
  issues: string[]
): Promise<CryptoKey | null> {
  const expectedKeys = [COSE_KTY, COSE_ALG, COSE_CRV, COSE_X, COSE_Y];
  for (const key of cose.keys()) {
    if (!expectedKeys.includes(key as number))
      issues.push(`unexpected COSE key parameter ${String(key)}`);
  }
  if (cose.get(COSE_KTY) !== COSE_KTY_EC2)
    issues.push(`COSE kty ${String(cose.get(COSE_KTY))} is not EC2`);
  if (cose.get(COSE_CRV) !== COSE_CRV_P256)
    issues.push(`COSE crv ${String(cose.get(COSE_CRV))} is not P-256`);
  const x = cose.get(COSE_X);
  const y = cose.get(COSE_Y);
  if (!(x instanceof Uint8Array) || x.length !== 32) issues.push('COSE x is not 32 bytes');
  if (!(y instanceof Uint8Array) || y.length !== 32) issues.push('COSE y is not 32 bytes');
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) return null;
  try {
    return await crypto.subtle.importKey(
      'raw',
      bs(concat(new Uint8Array([4]), x, y)),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );
  } catch (error) {
    issues.push(`COSE key is not a point on P-256: ${(error as Error).message}`);
    return null;
  }
}

/** Strict DER ECDSA-Sig-Value -> 64-byte r||s, or null with issues recorded. */
export function derToP1363(der: Uint8Array, issues: string[]): Uint8Array | null {
  const fail = (why: string) => {
    issues.push(`signature is not strict DER: ${why}`);
    return null;
  };
  if (der.length < 8 || der[0] !== 0x30) return fail('no SEQUENCE');
  if (der[1] & 0x80) return fail('long-form SEQUENCE length for a short signature');
  if (der[1] !== der.length - 2) return fail(`SEQUENCE length ${der[1]} != ${der.length - 2}`);
  let pos = 2;
  const ints: Uint8Array[] = [];
  for (let i = 0; i < 2; i++) {
    if (der[pos] !== 0x02) return fail('expected INTEGER');
    const length = der[pos + 1];
    if (length & 0x80) return fail('long-form INTEGER length');
    if (length === 0) return fail('empty INTEGER');
    const value = der.subarray(pos + 2, pos + 2 + length);
    if (value.length !== length) return fail('INTEGER overruns SEQUENCE');
    if (value[0] & 0x80) return fail('negative INTEGER');
    if (value[0] === 0 && length > 1 && !(value[1] & 0x80)) return fail('non-minimal INTEGER');
    const unsigned = value[0] === 0 && length > 1 ? value.subarray(1) : value;
    if (unsigned.length > 32) return fail('INTEGER longer than 32 bytes');
    const n = BigInt('0x' + Array.from(unsigned, (b) => b.toString(16).padStart(2, '0')).join(''));
    if (n === 0n || n >= P256_N) return fail('INTEGER out of [1, n-1]');
    const padded = new Uint8Array(32);
    padded.set(unsigned, 32 - unsigned.length);
    ints.push(padded);
    pos += 2 + length;
  }
  if (pos !== der.length) return fail('trailing bytes');
  return concat(ints[0], ints[1]);
}

function isInstanceOf(value: unknown, className: string): boolean {
  const ctor = (globalThis as Record<string, unknown>)[className];
  return typeof ctor === 'function' && value instanceof (ctor as new () => unknown);
}

function callMethod<T>(
  target: Record<string, unknown>,
  name: string,
  issues: string[]
): T | undefined {
  try {
    const method = target[name];
    if (typeof method !== 'function') {
      issues.push(`${name}() is missing`);
      return undefined;
    }
    return (method as () => T).call(target);
  } catch (error) {
    issues.push(`${name}() threw ${(error as Error).message}`);
    return undefined;
  }
}

function checkCredentialShell(credential: any, issues: string[]): Uint8Array | null {
  if (!credential || typeof credential !== 'object') {
    issues.push(`credential is ${credential === null ? 'null' : typeof credential}`);
    return null;
  }
  if (!isInstanceOf(credential, 'PublicKeyCredential'))
    issues.push('credential is not a PublicKeyCredential');
  if (credential.type !== 'public-key') issues.push(`credential.type is ${credential.type}`);
  if (!isArrayBuffer(credential.rawId)) {
    issues.push('credential.rawId is not an ArrayBuffer');
    return null;
  }
  const rawId = toBytes(credential.rawId);
  if (credential.id !== b64url(rawId)) {
    issues.push(`credential.id ${credential.id} is not the base64url of rawId`);
  }
  const attachment = credential.authenticatorAttachment;
  if (attachment !== null && attachment !== 'platform' && attachment !== 'cross-platform') {
    issues.push(`authenticatorAttachment ${attachment} is not a valid value`);
  }
  return rawId;
}

function jsonBuffer(
  issues: string[],
  label: string,
  json: unknown,
  bytes: Uint8Array | null
): void {
  if (bytes === null) return;
  if (!isB64url(json)) {
    issues.push(`toJSON().${label} is not unpadded base64url`);
    return;
  }
  if (!equalBytes(fromB64url(json), bytes))
    issues.push(`toJSON().${label} does not match the binary value`);
}

function checkExtensionResultsJSON(issues: string[], json: any, results: any): void {
  const prfResults = results?.prf?.results;
  if (!prfResults) return;
  for (const name of ['first', 'second']) {
    if (prfResults[name] === undefined) continue;
    const value = json?.prf?.results?.[name];
    if (!isB64url(value)) {
      issues.push(`toJSON().clientExtensionResults.prf.results.${name} is not base64url`);
    } else if (!equalBytes(fromB64url(value), toBytes(prfResults[name]))) {
      issues.push(`toJSON().clientExtensionResults.prf.results.${name} does not match`);
    }
  }
}

function checkPrfResults(
  issues: string[],
  results: any,
  requested: any,
  registration: boolean
): void {
  const prf = results?.prf;
  if (!requested) return;
  if (registration && typeof prf?.enabled !== 'boolean') {
    issues.push('prf was requested at registration but prf.enabled is missing (§10.1.4)');
  }
  if (!registration && prf && 'enabled' in prf) {
    issues.push('prf.enabled must not be present in an authentication result (§10.1.4)');
  }
  for (const name of ['first', 'second']) {
    const value = prf?.results?.[name];
    if (value === undefined) continue;
    if (!isArrayBuffer(value)) issues.push(`prf.results.${name} is not an ArrayBuffer`);
    else if (value.byteLength !== 32)
      issues.push(`prf.results.${name} is ${value.byteLength} bytes, not 32`);
  }
}

export async function verifyRegistration(
  credential: any,
  expected: RegistrationExpectation
): Promise<CredentialRecord> {
  const issues: string[] = [];
  const rawId = checkCredentialShell(credential, issues);
  const response = credential?.response;
  if (!isInstanceOf(response, 'AuthenticatorAttestationResponse')) {
    issues.push('response is not an AuthenticatorAttestationResponse');
  }
  if (!response) throw new ConformanceError(issues);

  const clientDataJSON = isArrayBuffer(response.clientDataJSON)
    ? toBytes(response.clientDataJSON)
    : null;
  if (!clientDataJSON) issues.push('response.clientDataJSON is not an ArrayBuffer');
  else {
    checkClientData(
      clientDataJSON,
      {
        type: 'webauthn.create',
        challenge: expected.challenge,
        origin: expected.origin,
        crossOrigin: expected.crossOrigin,
        topOrigin: expected.topOrigin,
      },
      issues
    );
  }

  let authData: Uint8Array | null = null;
  let parsed: ParsedAuthenticatorData | null = null;
  if (!isArrayBuffer(response.attestationObject)) {
    issues.push('response.attestationObject is not an ArrayBuffer');
  } else {
    try {
      const { value } = decodeCbor(toBytes(response.attestationObject));
      if (!(value instanceof Map)) throw new Error('attestation object is not a map');
      const keys = [...value.keys()];
      if (keys.join() !== 'fmt,attStmt,authData') {
        issues.push(
          `attestation object keys are [${keys.join(', ')}], expected fmt, attStmt, authData`
        );
      }
      const fmt = value.get('fmt');
      const attStmt = value.get('attStmt');
      if (fmt !== 'none') issues.push(`unexpected attestation format ${String(fmt)}`);
      if (!(attStmt instanceof Map) || attStmt.size !== 0)
        issues.push('"none" attestation needs an empty attStmt');
      const data = value.get('authData');
      if (!(data instanceof Uint8Array)) issues.push('authData is not a byte string');
      else authData = data;
    } catch (error) {
      issues.push(`attestation object: ${(error as Error).message}`);
    }
  }

  let publicKey: CryptoKey | null = null;
  let alg: number | undefined;
  if (authData) {
    parsed = parseAuthenticatorData(authData, issues);
  }
  if (parsed) {
    if (!equalBytes(parsed.rpIdHash, await sha256(expected.rpId))) {
      issues.push(`rpIdHash is not SHA-256("${expected.rpId}")`);
    }
    if (!(parsed.flags & FLAG_UP)) issues.push('UP flag clear');
    if (expected.requireUserVerification && !(parsed.flags & FLAG_UV))
      issues.push('UV required but clear');
    if (!(parsed.flags & FLAG_BE) && parsed.flags & FLAG_BS) issues.push('BS set without BE');
    if (!(parsed.flags & FLAG_AT)) issues.push('AT flag clear on a registration');
    if (parsed.flags & FLAG_ED && !parsed.extensions) issues.push('ED set without extensions');
    if (rawId && parsed.credentialId && !equalBytes(rawId, parsed.credentialId)) {
      issues.push('rawId differs from the credential ID in authenticator data');
    }
    if (parsed.credentialPublicKey) {
      alg = parsed.credentialPublicKey.get(COSE_ALG) as number;
      const params = expected.pubKeyCredParams?.length
        ? expected.pubKeyCredParams.filter((p) => p.type === 'public-key').map((p) => Number(p.alg))
        : [ES256, -257];
      if (!params.includes(alg))
        issues.push(`credential alg ${alg} is not one the RP offered (${params.join(', ')})`);
      publicKey = await importCoseKey(parsed.credentialPublicKey, issues);
    }

    // Level 3 convenience accessors must agree with the attestation object.
    const fromMethod = callMethod<ArrayBuffer>(response, 'getAuthenticatorData', issues);
    if (
      fromMethod !== undefined &&
      (!isArrayBuffer(fromMethod) || !equalBytes(toBytes(fromMethod), authData!))
    ) {
      issues.push('getAuthenticatorData() differs from authData in the attestation object');
    }
    const algFromMethod = callMethod<number>(response, 'getPublicKeyAlgorithm', issues);
    if (algFromMethod !== undefined && algFromMethod !== alg) {
      issues.push(`getPublicKeyAlgorithm() is ${algFromMethod}, COSE says ${alg}`);
    }
    const spki = callMethod<ArrayBuffer | null>(response, 'getPublicKey', issues);
    if (spki !== undefined && publicKey) {
      if (!isArrayBuffer(spki))
        issues.push('getPublicKey() is not an ArrayBuffer (ES256 must be exposed)');
      else {
        try {
          const imported = await crypto.subtle.importKey(
            'spki',
            bs(toBytes(spki)),
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
          );
          const a = new Uint8Array(await crypto.subtle.exportKey('raw', imported));
          const b = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
          if (!equalBytes(a, b)) issues.push('getPublicKey() is a different key than the COSE key');
        } catch (error) {
          issues.push(`getPublicKey() is not a valid SPKI: ${(error as Error).message}`);
        }
      }
    }
  }

  const transports = callMethod<string[]>(response, 'getTransports', issues) ?? [];
  if (!Array.isArray(transports) || transports.some((t) => typeof t !== 'string')) {
    issues.push('getTransports() is not a sequence of strings');
  } else {
    const sorted = [...new Set(transports)].sort();
    if (sorted.join() !== transports.join())
      issues.push('getTransports() is not sorted and unique (§5.2.1)');
  }

  const results = callMethod<any>(credential, 'getClientExtensionResults', issues);
  if (results !== undefined && (results === null || typeof results !== 'object')) {
    issues.push('getClientExtensionResults() is not an object');
  }
  checkPrfResults(issues, results, expected.extensions?.prf, true);
  if (expected.extensions?.credProps === true && typeof results?.credProps?.rk !== 'boolean') {
    issues.push('credProps was requested but credProps.rk is missing');
  }

  const json = callMethod<any>(credential, 'toJSON', issues);
  if (json) {
    try {
      JSON.stringify(credential);
    } catch (error) {
      issues.push(`JSON.stringify(credential) threw ${(error as Error).message}`);
    }
    if (json.id !== credential.id) issues.push('toJSON().id differs from id');
    jsonBuffer(issues, 'rawId', json.rawId, rawId);
    if (json.type !== 'public-key') issues.push('toJSON().type is not public-key');
    if (json.authenticatorAttachment !== credential.authenticatorAttachment) {
      issues.push('toJSON().authenticatorAttachment differs');
    }
    jsonBuffer(issues, 'response.clientDataJSON', json.response?.clientDataJSON, clientDataJSON);
    jsonBuffer(
      issues,
      'response.attestationObject',
      json.response?.attestationObject,
      isArrayBuffer(response.attestationObject) ? toBytes(response.attestationObject) : null
    );
    jsonBuffer(issues, 'response.authenticatorData', json.response?.authenticatorData, authData);
    if (json.response?.publicKeyAlgorithm !== alg)
      issues.push('toJSON().response.publicKeyAlgorithm differs');
    if (JSON.stringify(json.response?.transports) !== JSON.stringify(transports)) {
      issues.push('toJSON().response.transports differs from getTransports()');
    }
    checkExtensionResultsJSON(issues, json.clientExtensionResults, results);
  }

  if (issues.length > 0 || !parsed || !publicKey || !rawId || !parsed.credentialPublicKeyBytes) {
    throw new ConformanceError(issues.length ? issues : ['registration could not be parsed']);
  }
  return {
    id: credential.id,
    rawId,
    publicKey,
    publicKeyCose: parsed.credentialPublicKeyBytes,
    signCount: parsed.signCount,
    uvInitialized: Boolean(parsed.flags & FLAG_UV),
    transports,
    backupEligible: Boolean(parsed.flags & FLAG_BE),
    backupState: Boolean(parsed.flags & FLAG_BS),
    aaguid: parsed.aaguid!,
    userHandle: expected.userId,
    rpId: expected.rpId,
  };
}

export interface AuthenticationResult {
  signCount: number;
  flags: number;
  userHandle: Uint8Array | null;
  extensionResults: any;
}

export async function verifyAuthentication(
  credential: any,
  expected: AuthenticationExpectation
): Promise<AuthenticationResult> {
  const issues: string[] = [];
  const rawId = checkCredentialShell(credential, issues);
  const response = credential?.response;
  if (!isInstanceOf(response, 'AuthenticatorAssertionResponse')) {
    issues.push('response is not an AuthenticatorAssertionResponse');
  }
  if (!response) throw new ConformanceError(issues);
  const record = expected.record;

  if (rawId) {
    if (
      expected.allowCredentials?.length &&
      !expected.allowCredentials.some((id) => equalBytes(id, rawId))
    ) {
      issues.push('credential is not one of allowCredentials');
    }
    if (!equalBytes(rawId, record.rawId)) issues.push('rawId is not the registered credential');
  }

  let userHandle: Uint8Array | null = null;
  if (response.userHandle !== null && response.userHandle !== undefined) {
    if (!isArrayBuffer(response.userHandle))
      issues.push('userHandle is not an ArrayBuffer or null');
    else userHandle = toBytes(response.userHandle);
  }
  if (userHandle && !equalBytes(userHandle, record.userHandle))
    issues.push('userHandle is not the user.id given at registration');
  if (!expected.allowCredentials?.length && !userHandle) {
    issues.push('discoverable sign-in without a userHandle cannot identify the user');
  }

  const clientDataJSON = isArrayBuffer(response.clientDataJSON)
    ? toBytes(response.clientDataJSON)
    : null;
  if (!clientDataJSON) issues.push('response.clientDataJSON is not an ArrayBuffer');
  else {
    checkClientData(
      clientDataJSON,
      {
        type: 'webauthn.get',
        challenge: expected.challenge,
        origin: expected.origin,
        crossOrigin: expected.crossOrigin,
        topOrigin: expected.topOrigin,
      },
      issues
    );
  }

  const authData = isArrayBuffer(response.authenticatorData)
    ? toBytes(response.authenticatorData)
    : null;
  if (!authData) issues.push('response.authenticatorData is not an ArrayBuffer');
  const parsed = authData ? parseAuthenticatorData(authData, issues) : null;
  if (parsed) {
    if (!equalBytes(parsed.rpIdHash, await sha256(expected.rpId))) {
      issues.push(`rpIdHash is not SHA-256("${expected.rpId}")`);
    }
    if (!(parsed.flags & FLAG_UP)) issues.push('UP flag clear');
    if (expected.requireUserVerification && !(parsed.flags & FLAG_UV))
      issues.push('UV required but clear');
    if (!(parsed.flags & FLAG_BE) && parsed.flags & FLAG_BS) issues.push('BS set without BE');
    if (Boolean(parsed.flags & FLAG_BE) !== record.backupEligible) {
      issues.push('BE changed since registration (RPs must treat this as an error, §7.2)');
    }
    if (parsed.flags & FLAG_AT) issues.push('AT set on an assertion');
    const counterMoved = parsed.signCount > record.signCount;
    if (
      (parsed.signCount !== 0 || record.signCount !== 0) &&
      !counterMoved &&
      expected.strictCounter !== false
    ) {
      issues.push(`signCount ${parsed.signCount} did not advance past ${record.signCount}`);
    }
  }

  const signature = isArrayBuffer(response.signature) ? toBytes(response.signature) : null;
  if (!signature) issues.push('response.signature is not an ArrayBuffer');
  if (signature && authData && clientDataJSON) {
    const p1363 = derToP1363(signature, issues);
    if (p1363) {
      const signed = concat(authData, await sha256(clientDataJSON));
      const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        record.publicKey,
        bs(p1363),
        bs(signed)
      );
      if (!valid) issues.push('signature does not verify with the registered public key');
    }
  }

  const results = callMethod<any>(credential, 'getClientExtensionResults', issues);
  checkPrfResults(issues, results, expected.extensions?.prf, false);
  if (results && 'credProps' in results)
    issues.push('credProps is a registration-only extension (§10.1.3)');

  const json = callMethod<any>(credential, 'toJSON', issues);
  if (json) {
    try {
      JSON.stringify(credential);
    } catch (error) {
      issues.push(`JSON.stringify(credential) threw ${(error as Error).message}`);
    }
    jsonBuffer(issues, 'rawId', json.rawId, rawId);
    jsonBuffer(issues, 'response.clientDataJSON', json.response?.clientDataJSON, clientDataJSON);
    jsonBuffer(issues, 'response.authenticatorData', json.response?.authenticatorData, authData);
    jsonBuffer(issues, 'response.signature', json.response?.signature, signature);
    if (userHandle)
      jsonBuffer(issues, 'response.userHandle', json.response?.userHandle, userHandle);
    else if (json.response && 'userHandle' in json.response)
      issues.push('toJSON() carries a userHandle the response lacks');
    checkExtensionResultsJSON(issues, json.clientExtensionResults, results);
  }

  if (issues.length > 0 || !parsed)
    throw new ConformanceError(issues.length ? issues : ['assertion could not be parsed']);
  return {
    signCount: parsed.signCount,
    flags: parsed.flags,
    userHandle,
    extensionResults: results,
  };
}
