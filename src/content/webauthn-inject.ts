/**
 * WebAuthn Injection Script
 *
 * This script replaces the native WebAuthn API with our extension's implementation
 * to completely manage passkeys without showing the browser's UI.
 */

(function () {
  'use strict';

  type BufferInput =
    | string
    | ArrayBuffer
    | ArrayBufferView
    | { type: 'Buffer'; data: number[] }
    | null
    | undefined;

  interface PendingRequest {
    resolve: (value: Credential | null) => void;
    reject: (reason?: unknown) => void;
    timeoutId: number;
    nativeFallback?: () => Promise<Credential | null>;
  }

  interface PrfResults {
    first?: BufferInput;
    second?: BufferInput;
  }

  interface SerializedClientExtensionResults {
    prf?: {
      results?: PrfResults;
    };
  }

  interface NormalizedClientExtensionResults {
    credProps: { rk: boolean };
    prf?: {
      results: {
        first?: ArrayBuffer;
        second?: ArrayBuffer;
      };
    };
  }

  /** Credential as the content script posts it: buffers are base64 strings. */
  interface SerializedResponse {
    clientDataJSON: string;
    attestationObject?: string;
    authenticatorData?: string;
    publicKey?: string | null;
    publicKeyAlgorithm?: number;
    transports?: string[];
    signature?: string;
    userHandle?: string | null;
  }

  interface SerializedCredential {
    id: string;
    rawId: string;
    type: string;
    response: SerializedResponse;
    authenticatorAttachment?: string | null;
    clientExtensionResults?: SerializedClientExtensionResults | null;
  }

  // Debug mode controlled by page context (silent by default)
  const DEBUG = false;

  // Store pending requests
  const pendingRequests = new Map<string, PendingRequest>();

  // Listen for responses from content script
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;

    if (event.data?.source === 'PASSKEY_VAULT_CONTENT') {
      const { requestId, result } = event.data;

      if (pendingRequests.has(requestId)) {
        const { resolve, reject, timeoutId, nativeFallback } = pendingRequests.get(requestId)!;
        pendingRequests.delete(requestId);
        if (timeoutId) {
          clearTimeout(timeoutId);
        }

        if (result.success) {
          const credential = result.credential ? buildCredential(result.credential) : null;
          resolve(credential || result);
        } else if (result.passthrough) {
          if (DEBUG) console.log('Fenko Vault: Passing WebAuthn request to native browser UI');
          if (!nativeFallback) {
            reject(new DOMException('Native WebAuthn fallback is unavailable.', 'NotAllowedError'));
            return;
          }
          nativeFallback().then(resolve).catch(reject);
        } else {
          // Create proper DOMException for WebAuthn errors
          const errorName = result.name || 'NotAllowedError';
          const errorMessage = result.error || 'The operation was aborted.';
          const error = new DOMException(errorMessage, errorName);
          if (result.blockNativeFallback) {
            Object.defineProperty(error, '__passkeyVaultBlockNativeFallback', { value: true });
          }
          reject(error);
        }
      }
    }
  });

  // Hook WebAuthn API
  if (navigator.credentials) {
    const nativeCreate = navigator.credentials.create?.bind(navigator.credentials);
    const nativeGet = navigator.credentials.get?.bind(navigator.credentials);

    // Override create: fully intercept and handle passkey creation internally
    navigator.credentials.create = async function (options?: CredentialCreationOptions) {
      if (DEBUG) console.log('Fenko Vault: Intercepted create request', options);

      // Only intercept publicKey (WebAuthn) requests
      if (!options?.publicKey) {
        if (nativeCreate) {
          return nativeCreate(options);
        }
        throw new Error('navigator.credentials.create is not available');
      }

      const REQUEST_TIMEOUT_MS = 60000; // 60 seconds for user interaction
      const publicKey = options.publicKey;

      return new Promise((resolve, reject) => {
        const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const timeoutId = window.setTimeout(() => {
          pendingRequests.delete(requestId);
          reject(new DOMException('The operation timed out.', 'NotAllowedError'));
        }, REQUEST_TIMEOUT_MS);

        pendingRequests.set(requestId, {
          resolve,
          reject,
          timeoutId,
          nativeFallback: nativeCreate ? () => nativeCreate(options) : undefined,
        });

        // Serialize the options for message passing
        const serializablePayload = {
          publicKey: {
            rp: publicKey.rp,
            rpId: publicKey.rp?.id || window.location.hostname,
            user: {
              id: serializeBufferSource(publicKey.user?.id),
              name: publicKey.user?.name,
              displayName: publicKey.user?.displayName,
            },
            challenge: serializeBufferSource(publicKey.challenge),
            pubKeyCredParams: publicKey.pubKeyCredParams,
            timeout: publicKey.timeout,
            excludeCredentials: publicKey.excludeCredentials?.map((cred) => ({
              id: serializeBufferSource(cred.id),
              type: cred.type,
              transports: cred.transports,
            })),
            authenticatorSelection: publicKey.authenticatorSelection,
            attestation: publicKey.attestation,
            extensions: publicKey.extensions,
          },
          origin: window.location.origin,
        };

        if (DEBUG) console.log('Fenko Vault: Sending CREATE_PASSKEY request', serializablePayload);

        window.postMessage(
          {
            source: 'PASSKEY_VAULT_PAGE',
            type: 'PASSKEY_CREATE_REQUEST',
            payload: serializablePayload,
            requestId,
          },
          '*'
        );
      });
    };

    // Override get: try extension-managed passkeys, fall back to native WebAuthn on failure.
    navigator.credentials.get = async function (options?: CredentialRequestOptions) {
      if (DEBUG) console.log('Fenko Vault: Intercepted get request', options);

      // Only intercept publicKey (WebAuthn) requests
      if (!options?.publicKey) {
        if (nativeGet) {
          return nativeGet(options);
        }
        throw new Error('navigator.credentials.get is not available');
      }

      const REQUEST_TIMEOUT_MS = 60000; // 60 seconds for user interaction
      const publicKey = options.publicKey;

      try {
        return await new Promise((resolve, reject) => {
          const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
          const timeoutId = window.setTimeout(() => {
            pendingRequests.delete(requestId);
            reject(new DOMException('The operation timed out.', 'NotAllowedError'));
          }, REQUEST_TIMEOUT_MS);

          pendingRequests.set(requestId, {
            resolve,
            reject,
            timeoutId,
            nativeFallback: nativeGet ? () => nativeGet(options) : undefined,
          });

          // Serialize the options for message passing
          const serializablePayload = {
            publicKey: {
              rpId: publicKey.rpId || window.location.hostname,
              challenge: serializeBufferSource(publicKey.challenge),
              timeout: publicKey.timeout,
              allowCredentials: publicKey.allowCredentials?.map((cred) => ({
                id: serializeBufferSource(cred.id),
                type: cred.type,
                transports: cred.transports,
              })),
              userVerification: publicKey.userVerification,
              extensions: publicKey.extensions,
            },
            mediation: options.mediation,
            origin: window.location.origin,
          };

          if (DEBUG) console.log('Fenko Vault: Sending GET_PASSKEY request', serializablePayload);

          window.postMessage(
            {
              source: 'PASSKEY_VAULT_PAGE',
              type: 'PASSKEY_GET_REQUEST',
              payload: serializablePayload,
              requestId,
            },
            '*'
          );
        });
      } catch (e: unknown) {
        const blocksNativeFallback = Boolean(
          (e as { __passkeyVaultBlockNativeFallback?: boolean }).__passkeyVaultBlockNativeFallback
        );
        if (blocksNativeFallback || !nativeGet) {
          throw e;
        }

        const errorMessage = e instanceof Error ? e.message : String(e);

        if (DEBUG) {
          console.warn(
            'Fenko Vault: Extension get failed, falling back to native WebAuthn',
            errorMessage
          );
        }

        return nativeGet(options);
      }
    };

    if (DEBUG) console.log('Fenko Vault: WebAuthn API hooked successfully');
  } else {
    // navigator.credentials is only exposed in secure contexts (HTTPS or
    // http://localhost). On plain-HTTP origins the API is absent and there is
    // nothing to hook — not an error, just a no-op for this page.
    if (DEBUG) {
      console.log(
        'Fenko Vault: navigator.credentials unavailable (non-secure context), skipping hook'
      );
    }
  }

  /**
   * Rebuild the credential on the browser's own prototypes.
   *
   * The object arrives through postMessage as a plain `{}`. Sites that branch
   * on `response instanceof AuthenticatorAttestationResponse` then pick the
   * wrong serialiser (issue #8). Placing our own data properties on top of the
   * native prototype makes `instanceof` and `Object.prototype.toString` report
   * the platform class while every read still hits our property, never a
   * native getter that would throw "Illegal invocation".
   *
   *   PublicKeyCredential.prototype        AuthenticatorAttestationResponse.prototype
   *              ^                                          ^
   *   { id, rawId, response, ... }   --->   { clientDataJSON, attestationObject, getTransports, ... }
   */
  function buildCredential(raw: SerializedCredential): PublicKeyCredential {
    const isRegistration = raw.response.attestationObject != null;
    const response = isRegistration
      ? buildAttestationResponse(raw.response)
      : buildAssertionResponse(raw.response);
    const extensions = normalizeClientExtensionResults(raw.clientExtensionResults);
    const rawId = base64ToArrayBuffer(raw.rawId);
    const attachment = raw.authenticatorAttachment ?? null;

    return onNativePrototype('PublicKeyCredential', {
      id: raw.id,
      type: raw.type,
      rawId,
      response,
      authenticatorAttachment: attachment,
      getClientExtensionResults: () => extensions,
      toJSON: () => ({
        id: raw.id,
        rawId: arrayBufferToBase64URL(rawId),
        type: raw.type,
        authenticatorAttachment: attachment,
        clientExtensionResults: extensions,
        response: isRegistration
          ? registrationResponseJSON(raw.response)
          : authenticationResponseJSON(raw.response),
      }),
    }) as PublicKeyCredential;
  }

  function buildAttestationResponse(raw: SerializedResponse): object {
    const authenticatorData = optionalBuffer(raw.authenticatorData);
    const publicKey = optionalBuffer(raw.publicKey);
    const transports = raw.transports ?? [];

    return onNativePrototype('AuthenticatorAttestationResponse', {
      clientDataJSON: base64ToArrayBuffer(raw.clientDataJSON),
      attestationObject: base64ToArrayBuffer(raw.attestationObject),
      getTransports: () => transports.slice(),
      getAuthenticatorData: () => authenticatorData,
      getPublicKey: () => publicKey,
      getPublicKeyAlgorithm: () => raw.publicKeyAlgorithm,
    });
  }

  function buildAssertionResponse(raw: SerializedResponse): object {
    return onNativePrototype('AuthenticatorAssertionResponse', {
      clientDataJSON: base64ToArrayBuffer(raw.clientDataJSON),
      authenticatorData: base64ToArrayBuffer(raw.authenticatorData),
      signature: base64ToArrayBuffer(raw.signature),
      userHandle: optionalBuffer(raw.userHandle),
    });
  }

  /** RegistrationResponseJSON (WebAuthn Level 3 §5.8.1.1). */
  function registrationResponseJSON(raw: SerializedResponse) {
    const json: Record<string, unknown> = {
      clientDataJSON: toBase64URL(raw.clientDataJSON),
      attestationObject: toBase64URL(raw.attestationObject),
      authenticatorData: toBase64URL(raw.authenticatorData),
      publicKeyAlgorithm: raw.publicKeyAlgorithm,
      transports: raw.transports ?? [],
    };
    if (raw.publicKey) {
      json.publicKey = toBase64URL(raw.publicKey);
    }
    return json;
  }

  /** AuthenticationResponseJSON (WebAuthn Level 3 §5.8.1.2). */
  function authenticationResponseJSON(raw: SerializedResponse) {
    const json: Record<string, unknown> = {
      clientDataJSON: toBase64URL(raw.clientDataJSON),
      authenticatorData: toBase64URL(raw.authenticatorData),
      signature: toBase64URL(raw.signature),
    };

    // JSON omits an absent handle; the response object still exposes null.
    if (raw.userHandle != null) {
      json.userHandle = toBase64URL(raw.userHandle);
    }
    return json;
  }

  /**
   * Create an object inheriting from the named native class (or a plain
   * object where the realm lacks it) and define `members` as own properties.
   * defineProperty is required: the native prototypes carry getter-only
   * accessors, so plain assignment would throw under strict mode.
   */
  function onNativePrototype(className: string, members: Record<string, unknown>): object {
    const ctor = (window as unknown as Record<string, unknown>)[className];
    const proto = typeof ctor === 'function' ? ctor.prototype : Object.prototype;
    const obj = Object.create(proto);

    for (const name of Object.keys(members)) {
      Object.defineProperty(obj, name, {
        value: members[name],
        writable: true,
        enumerable: true,
        configurable: true,
      });
    }

    shadowUnknownMembers(obj, proto);
    return obj;
  }

  /**
   * Any native member we did not anticipate (a future spec addition, a vendor
   * extra) becomes an own `undefined` rather than a trap that throws
   * "Illegal invocation" on a synthetic receiver.
   */
  function shadowUnknownMembers(obj: object, proto: object): void {
    for (let p = proto; p && p !== Object.prototype; p = Object.getPrototypeOf(p)) {
      for (const name of Object.getOwnPropertyNames(p)) {
        if (name === 'constructor' || Object.prototype.hasOwnProperty.call(obj, name)) {
          continue;
        }
        Object.defineProperty(obj, name, { value: undefined, writable: true, configurable: true });
      }
    }
  }

  function optionalBuffer(value: BufferInput): ArrayBuffer | null {
    return value ? base64ToArrayBuffer(value) : null;
  }

  function toBase64URL(value: BufferInput): string {
    return arrayBufferToBase64URL(base64ToArrayBuffer(value));
  }

  /**
   * Serialize a BufferSource (ArrayBuffer, TypedArray, DataView) to base64url string
   */
  function normalizeClientExtensionResults(
    results: SerializedClientExtensionResults | null | undefined
  ): NormalizedClientExtensionResults {
    const base: NormalizedClientExtensionResults = { credProps: { rk: true } };
    if (!results?.prf?.results) {
      return base;
    }

    const prfResults: { first?: ArrayBuffer; second?: ArrayBuffer } = {};
    if (results.prf.results.first) {
      prfResults.first = base64ToArrayBuffer(results.prf.results.first);
    }
    if (results.prf.results.second) {
      prfResults.second = base64ToArrayBuffer(results.prf.results.second);
    }

    if (prfResults.first || prfResults.second) {
      base.prf = { results: prfResults };
    }

    return base;
  }

  /**
   * Serialize a BufferSource (ArrayBuffer, TypedArray, DataView) to base64url string
   */
  function serializeBufferSource(value: BufferInput): string | null {
    if (value == null) {
      return null;
    }
    if (typeof value === 'string') {
      return value; // Already a string (possibly base64)
    }
    if (value instanceof ArrayBuffer) {
      return arrayBufferToBase64URL(value);
    }
    if (ArrayBuffer.isView(value)) {
      return arrayBufferToBase64URL(value.buffer as ArrayBuffer);
    }
    // Unknown type, try to convert
    return String(value);
  }

  /**
   * Convert ArrayBuffer to base64url string (URL-safe base64 without padding)
   */
  function arrayBufferToBase64URL(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i] & 0xff);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Convert base64 or base64url string to ArrayBuffer
   */
  function base64ToArrayBuffer(base64url: BufferInput): ArrayBuffer {
    // If already an ArrayBuffer, return it
    if (base64url instanceof ArrayBuffer) {
      return base64url;
    }
    // If Uint8Array, return its buffer
    if (base64url instanceof Uint8Array) {
      return base64url.buffer as ArrayBuffer;
    }
    // Handle any other ArrayBufferView (e.g. Int8Array, DataView)
    if (ArrayBuffer.isView(base64url)) {
      return base64url.buffer as ArrayBuffer;
    }
    if (
      typeof base64url === 'object' &&
      base64url?.type === 'Buffer' &&
      Array.isArray(base64url.data)
    ) {
      return new Uint8Array(base64url.data).buffer;
    }
    if (base64url == null) {
      throw new TypeError('Unsupported base64 input type: null/undefined');
    }
    if (typeof base64url !== 'string') {
      base64url = String(base64url);
    }

    // Validate the base64url string before conversion
    if (base64url.length === 0) {
      throw new Error('Empty base64 string');
    }

    // Convert from base64url to base64
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding if needed
    const padding = (4 - (base64.length % 4)) % 4;
    if (padding > 0) {
      base64 += '='.repeat(padding);
    }

    try {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i) & 0xff;
      }
      return bytes.buffer;
    } catch (e) {
      console.error('base64ToArrayBuffer failed for input:', base64url);
      console.error('Converted to:', base64);
      console.error('Error:', e);
      throw e;
    }
  }
})();
