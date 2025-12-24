/**
 * WebAuthn Injection Script
 *
 * This script replaces the native WebAuthn API with our extension's implementation
 * to completely manage passkeys without showing the browser's UI.
 */

(function () {
  'use strict';

  console.log('PassKey Vault: WebAuthn injection script loaded');

  // Store pending requests
  const pendingRequests = new Map();

  // Listen for responses from content script
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;

    if (event.data?.source === 'PASSKEY_VAULT_CONTENT') {
      const { type, requestId, result } = event.data;

      if (pendingRequests.has(requestId)) {
        const { resolve, reject, timeoutId } = pendingRequests.get(requestId);
        pendingRequests.delete(requestId);
        if (timeoutId) {
          clearTimeout(timeoutId);
        }

        if (result.success) {
          // Convert the plain object to a proper credential-like object with the required methods
          const credential = result.credential;
          if (credential) {
            // Convert base64 back to ArrayBuffer
            credential.rawId = base64ToArrayBuffer(credential.rawId);
            credential.response.clientDataJSON = base64ToArrayBuffer(
              credential.response.clientDataJSON
            );
            if (credential.response.attestationObject) {
              credential.response.attestationObject = base64ToArrayBuffer(
                credential.response.attestationObject
              );
            }
            if (credential.response.authenticatorData) {
              credential.response.authenticatorData = base64ToArrayBuffer(
                credential.response.authenticatorData
              );
            }
            if (credential.response.signature) {
              credential.response.signature = base64ToArrayBuffer(credential.response.signature);
            }
            if (credential.response.userHandle) {
              credential.response.userHandle = base64ToArrayBuffer(credential.response.userHandle);
            }

            const normalizedClientExtensions = normalizeClientExtensionResults(
              credential.clientExtensionResults
            );

            // Add the required methods
            credential.getClientExtensionResults = function () {
              return normalizedClientExtensions;
            };
            credential.toJSON = function () {
              return {
                id: this.id,
                rawId: arrayBufferToBase64URL(this.rawId),
                type: this.type,
                response: {
                  clientDataJSON: arrayBufferToBase64URL(this.response.clientDataJSON),
                  attestationObject: this.response.attestationObject
                    ? arrayBufferToBase64URL(this.response.attestationObject)
                    : undefined,
                  authenticatorData: this.response.authenticatorData
                    ? arrayBufferToBase64URL(this.response.authenticatorData)
                    : undefined,
                  signature: this.response.signature
                    ? arrayBufferToBase64URL(this.response.signature)
                    : undefined,
                  userHandle: this.response.userHandle
                    ? arrayBufferToBase64URL(this.response.userHandle)
                    : undefined,
                },
                authenticatorAttachment: this.authenticatorAttachment,
                clientExtensionResults: this.getClientExtensionResults(),
              };
            };
          }
          resolve(credential || result);
        } else {
          // Create proper DOMException for WebAuthn errors
          const errorName = result.name || 'NotAllowedError';
          const errorMessage = result.error || 'The operation was aborted.';
          reject(new DOMException(errorMessage, errorName));
        }
      }
    }
  });

  // Hook WebAuthn API
  if (navigator.credentials) {
    const nativeCreate = navigator.credentials.create?.bind(navigator.credentials);
    const nativeGet = navigator.credentials.get?.bind(navigator.credentials);

    // Override create: fully intercept and handle passkey creation internally
    navigator.credentials.create = async function (options: any) {
      console.log('PassKey Vault: Intercepted create request', options);

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

        pendingRequests.set(requestId, { resolve, reject, timeoutId });

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
            excludeCredentials: publicKey.excludeCredentials?.map((cred: any) => ({
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

        console.log('PassKey Vault: Sending CREATE_PASSKEY request', serializablePayload);

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
    navigator.credentials.get = async function (options: any) {
      console.log('PassKey Vault: Intercepted get request', options);

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

          pendingRequests.set(requestId, { resolve, reject, timeoutId });

          // Serialize the options for message passing
          const serializablePayload = {
            publicKey: {
              rpId: publicKey.rpId || window.location.hostname,
              challenge: serializeBufferSource(publicKey.challenge),
              timeout: publicKey.timeout,
              allowCredentials: publicKey.allowCredentials?.map((cred: any) => ({
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

          console.log('PassKey Vault: Sending GET_PASSKEY request', serializablePayload);

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
      } catch (e: any) {
        // Check if this is a "no passkeys found" error - this is expected and should silently fall back
        const isNoPasskeysError =
          e?.message?.includes('No passkeys found') || e?.message?.includes('not found');

        if (isNoPasskeysError) {
          console.log('PassKey Vault: No stored passkeys for this site, using native WebAuthn');
        } else {
          console.warn(
            'PassKey Vault: Extension get failed, falling back to native WebAuthn',
            e?.message || e
          );
        }

        if (nativeGet) {
          return nativeGet(options);
        }
        throw e;
      }
    };

    console.log('PassKey Vault: WebAuthn API hooked successfully');
  } else {
    console.warn('PassKey Vault: navigator.credentials not found, cannot hook');
  }

  /**
   * Serialize a BufferSource (ArrayBuffer, TypedArray, DataView) to base64url string
   */
  function normalizeClientExtensionResults(results: any): any {
    const base: any = { credProps: { rk: true } };
    if (!results?.prf?.results) {
      return base;
    }

    const prfResults: any = {};
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
  function serializeBufferSource(value: any): string | null {
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
  function base64ToArrayBuffer(base64url: any): ArrayBuffer {
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
    if (base64url?.type === 'Buffer' && Array.isArray(base64url.data)) {
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
