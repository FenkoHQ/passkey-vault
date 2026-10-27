/**
 * Credentials assembled from raw parts, on the same native prototypes the
 * vault uses, so the strict verifier can be pointed at spec test vectors and
 * at deliberately corrupted copies of real vault credentials.
 */

import { b64url, toBytes } from './bytes';

export interface CredentialParts {
  id?: string;
  rawId: Uint8Array;
  authenticatorAttachment?: string | null;
  clientDataJSON: Uint8Array;
  // Registration
  attestationObject?: Uint8Array;
  authenticatorData?: Uint8Array;
  publicKey?: Uint8Array | null;
  publicKeyAlgorithm?: number;
  transports?: string[];
  // Authentication
  signature?: Uint8Array;
  userHandle?: Uint8Array | null;
  extensionResults?: Record<string, unknown>;
}

function buffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

function on(className: string, members: Record<string, unknown>): any {
  const ctor = (globalThis as Record<string, unknown>)[className] as
    | { prototype: object }
    | undefined;
  const object = Object.create(ctor ? ctor.prototype : Object.prototype);
  for (const [name, value] of Object.entries(members)) {
    Object.defineProperty(object, name, {
      value,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return object;
}

export function syntheticCredential(parts: CredentialParts): any {
  const registration = parts.attestationObject !== undefined;
  const id = parts.id ?? b64url(parts.rawId);
  const extensionResults = parts.extensionResults ?? {};
  const response = registration
    ? on('AuthenticatorAttestationResponse', {
        clientDataJSON: buffer(parts.clientDataJSON),
        attestationObject: buffer(parts.attestationObject!),
        getAuthenticatorData: () => buffer(parts.authenticatorData!),
        getPublicKey: () => (parts.publicKey ? buffer(parts.publicKey) : null),
        getPublicKeyAlgorithm: () => parts.publicKeyAlgorithm,
        getTransports: () => (parts.transports ?? []).slice(),
      })
    : on('AuthenticatorAssertionResponse', {
        clientDataJSON: buffer(parts.clientDataJSON),
        authenticatorData: buffer(parts.authenticatorData!),
        signature: buffer(parts.signature!),
        userHandle: parts.userHandle ? buffer(parts.userHandle) : null,
      });
  const json = registration
    ? {
        clientDataJSON: b64url(parts.clientDataJSON),
        attestationObject: b64url(parts.attestationObject!),
        authenticatorData: b64url(parts.authenticatorData!),
        ...(parts.publicKey && { publicKey: b64url(parts.publicKey) }),
        publicKeyAlgorithm: parts.publicKeyAlgorithm,
        transports: parts.transports ?? [],
      }
    : {
        clientDataJSON: b64url(parts.clientDataJSON),
        authenticatorData: b64url(parts.authenticatorData!),
        signature: b64url(parts.signature!),
        ...(parts.userHandle && { userHandle: b64url(parts.userHandle) }),
      };
  return on('PublicKeyCredential', {
    id,
    type: 'public-key',
    rawId: buffer(parts.rawId),
    authenticatorAttachment: parts.authenticatorAttachment ?? null,
    response,
    getClientExtensionResults: () => extensionResults,
    toJSON: () => ({
      id,
      rawId: b64url(parts.rawId),
      type: 'public-key',
      authenticatorAttachment: parts.authenticatorAttachment ?? null,
      clientExtensionResults: {},
      response: json,
    }),
  });
}

/** The parts of a credential the vault returned, for mutation. */
export function partsOf(credential: any): CredentialParts {
  const response = credential.response;
  const registration = response.attestationObject !== undefined;
  return registration
    ? {
        rawId: toBytes(credential.rawId),
        authenticatorAttachment: credential.authenticatorAttachment,
        clientDataJSON: toBytes(response.clientDataJSON),
        attestationObject: toBytes(response.attestationObject),
        authenticatorData: toBytes(response.getAuthenticatorData()),
        publicKey: response.getPublicKey() ? toBytes(response.getPublicKey()) : null,
        publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
        transports: response.getTransports(),
      }
    : {
        rawId: toBytes(credential.rawId),
        authenticatorAttachment: credential.authenticatorAttachment,
        clientDataJSON: toBytes(response.clientDataJSON),
        authenticatorData: toBytes(response.authenticatorData),
        signature: toBytes(response.signature),
        userHandle: response.userHandle ? toBytes(response.userHandle) : null,
      };
}
