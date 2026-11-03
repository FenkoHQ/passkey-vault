/**
 * Ceremony options as relying parties build them.
 *
 * Servers send options as JSON with base64url buffers (WebAuthn L3 §5.1.8,
 * PublicKeyCredentialCreationOptionsJSON); pages turn them into
 * BufferSources before calling navigator.credentials, via
 * PublicKeyCredential.parseCreationOptionsFromJSON() or a library such as
 * @github/webauthn-json. These helpers do the same conversion, with buffers
 * built in the page realm so `instanceof ArrayBuffer` holds as on a real page.
 */

import { b64url, fromB64url } from './bytes';

type Json = Record<string, any>;

function buffer(text: string): ArrayBuffer {
  const bytes = fromB64url(text);
  const out = new ArrayBuffer(bytes.length);
  new Uint8Array(out).set(bytes);
  return out;
}

function descriptor(json: Json) {
  return { ...json, id: buffer(json.id) };
}

function prfValues(json: Json | undefined) {
  if (!json) return json;
  const out: Json = { first: buffer(json.first) };
  if (json.second !== undefined) out.second = buffer(json.second);
  return out;
}

function extensions(json: Json | undefined) {
  if (!json) return json;
  const out: Json = { ...json };
  if (json.prf) {
    out.prf = {};
    if (json.prf.eval) out.prf.eval = prfValues(json.prf.eval);
    if (json.prf.evalByCredential) {
      out.prf.evalByCredential = Object.fromEntries(
        Object.entries(json.prf.evalByCredential as Json).map(([k, v]) => [k, prfValues(v as Json)])
      );
    }
  }
  if (json.largeBlob?.write)
    out.largeBlob = { ...json.largeBlob, write: buffer(json.largeBlob.write) };
  return out;
}

export function creationOptionsFromJSON(json: Json): PublicKeyCredentialCreationOptions {
  return {
    ...json,
    challenge: buffer(json.challenge),
    user: { ...json.user, id: buffer(json.user.id) },
    excludeCredentials: json.excludeCredentials?.map(descriptor),
    extensions: extensions(json.extensions),
  } as PublicKeyCredentialCreationOptions;
}

export function requestOptionsFromJSON(json: Json): PublicKeyCredentialRequestOptions {
  return {
    ...json,
    challenge: buffer(json.challenge),
    allowCredentials: json.allowCredentials?.map(descriptor),
    extensions: extensions(json.extensions),
  } as PublicKeyCredentialRequestOptions;
}

let counter = 0;

/** Fresh random bytes, distinct per call. */
export function random(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  bytes[0] = counter++ & 0xff;
  return bytes;
}

/** A typical modern registration request (SimpleWebAuthn defaults, a passkey-first RP). */
export function registrationJSON(overrides: Json = {}): Json {
  return {
    challenge: b64url(random(32)),
    rp: { name: 'Example', id: 'example.com' },
    user: { id: b64url(random(32)), name: 'alice@example.com', displayName: 'Alice' },
    pubKeyCredParams: [
      { type: 'public-key', alg: -8 },
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
    ],
    timeout: 60000,
    attestation: 'none',
    excludeCredentials: [],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    extensions: { credProps: true },
    ...overrides,
  };
}

export function authenticationJSON(overrides: Json = {}): Json {
  return {
    challenge: b64url(random(32)),
    rpId: 'example.com',
    allowCredentials: [],
    userVerification: 'preferred',
    timeout: 60000,
    ...overrides,
  };
}
