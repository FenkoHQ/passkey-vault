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
    /** Stop listening to the page's AbortSignal once the request settles. */
    detachSignal: () => void;
  }

  interface PrfResults {
    first?: BufferInput;
    second?: BufferInput;
  }

  interface SerializedClientExtensionResults {
    credProps?: { rk?: boolean };
    prf?: {
      enabled?: boolean;
      results?: PrfResults;
    };
  }

  interface NormalizedClientExtensionResults {
    credProps?: { rk: boolean };
    prf?: {
      enabled?: boolean;
      results?: {
        first: ArrayBuffer;
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

  // WebAuthn Level 3 §15.1: the recommended range for a ceremony timeout,
  // and the default when the relying party gives none.
  const MIN_TIMEOUT_MS = 300000;
  const MAX_TIMEOUT_MS = 600000;
  const DEFAULT_TIMEOUT_MS = 300000;

  // Listen for responses from content script
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;

    if (event.data?.source === 'PASSKEY_VAULT_CONTENT') {
      const { requestId, result } = event.data;

      if (pendingRequests.has(requestId)) {
        const pending = pendingRequests.get(requestId)!;
        pendingRequests.delete(requestId);
        if (pending.timeoutId) {
          clearTimeout(pending.timeoutId);
        }
        pending.detachSignal();
        settle(pending, result);
      }
    }
  });

  /**
   * Settle a request with the content script's answer. The request is
   * already off the pending list and its timer cleared, so this must settle
   * it whatever the answer holds: an answer that cannot be turned into a
   * credential rejects, rather than leaving the page's promise unsettled.
   */
  function settle(pending: PendingRequest, result: unknown): void {
    const { resolve, reject, nativeFallback } = pending;
    try {
      if (!result || typeof result !== 'object') {
        throw new TypeError('No result');
      }
      const answer = result as Record<string, unknown>;
      if (answer.success) {
        if (!answer.credential) {
          throw new TypeError('No credential');
        }
        resolve(buildCredential(answer.credential as SerializedCredential));
      } else if (answer.passthrough) {
        if (DEBUG) console.log('Fenko Vault: Passing WebAuthn request to native browser UI');
        if (!nativeFallback) {
          reject(new DOMException('Native WebAuthn fallback is unavailable.', 'NotAllowedError'));
          return;
        }
        nativeFallback().then(resolve).catch(reject);
      } else {
        // Create proper DOMException for WebAuthn errors
        const errorName = (answer.name as string) || 'NotAllowedError';
        const errorMessage = (answer.error as string) || 'The operation was aborted.';
        const error = new DOMException(errorMessage, errorName);
        if (answer.blockNativeFallback) {
          Object.defineProperty(error, '__passkeyVaultBlockNativeFallback', { value: true });
        }
        reject(error);
      }
    } catch (cause) {
      if (DEBUG) console.warn('Fenko Vault: Unusable answer from the vault', cause);
      // The user already dealt with the vault, so do not open another prompt.
      const error = new DOMException(
        'The passkey vault returned a credential that could not be read.',
        'UnknownError'
      );
      Object.defineProperty(error, '__passkeyVaultBlockNativeFallback', { value: true });
      reject(error);
    }
  }

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

      // Converted before anything else, as the browser's bindings do: a bad
      // option rejects with TypeError and never reaches the vault.
      const publicKey = convertCreationOptions(options.publicKey);

      return new Promise((resolve, reject) => {
        const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const tracked = trackRequest(
          requestId,
          {
            resolve,
            reject,
            nativeFallback: nativeCreate ? () => nativeCreate(options) : undefined,
          },
          options.signal,
          ceremonyTimeout(publicKey.timeout, false)
        );
        if (!tracked) {
          return;
        }

        const serializablePayload = {
          publicKey,
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

      const publicKey = convertRequestOptions(options.publicKey);
      const mediation = options.mediation === undefined ? undefined : `${options.mediation}`;

      try {
        return await new Promise((resolve, reject) => {
          const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
          const tracked = trackRequest(
            requestId,
            {
              resolve,
              reject,
              nativeFallback: nativeGet ? () => nativeGet(options) : undefined,
            },
            options.signal,
            ceremonyTimeout(publicKey.timeout, mediation === 'conditional')
          );
          if (!tracked) {
            return;
          }

          const serializablePayload = {
            publicKey,
            mediation,
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
        // A page that aborted its request wants no prompt at all.
        if (blocksNativeFallback || options.signal?.aborted || !nativeGet) {
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
   * Register a request awaiting the content script, and stop it when it times
   * out or the page aborts it through options.signal. Stopping tells the
   * content script to cancel too, so its dialog closes and no passkey is
   * created or signed after the page has stopped waiting. Neither outcome
   * falls back to the native prompt: the user already ignored the vault's
   * dialog, or the page no longer wants an answer. Returns false, with the
   * promise rejected, when the signal was aborted before the request began.
   */
  function trackRequest(
    requestId: string,
    handlers: Pick<PendingRequest, 'resolve' | 'reject' | 'nativeFallback'>,
    signal: AbortSignal | null | undefined,
    timeoutMs: number | null
  ): boolean {
    if (signal?.aborted) {
      handlers.reject(abortReason(signal));
      return false;
    }

    const stop = (reason: unknown) => {
      const pending = pendingRequests.get(requestId);
      if (!pending) {
        return;
      }
      pendingRequests.delete(requestId);
      clearTimeout(pending.timeoutId);
      pending.detachSignal();
      window.postMessage(
        { source: 'PASSKEY_VAULT_PAGE', type: 'PASSKEY_CANCEL_REQUEST', requestId },
        '*'
      );
      handlers.reject(reason);
    };

    const onAbort = () => stop(abortReason(signal!));
    const timeoutId =
      timeoutMs === null
        ? 0
        : window.setTimeout(() => {
            const error = new DOMException('The operation timed out.', 'NotAllowedError');
            Object.defineProperty(error, '__passkeyVaultBlockNativeFallback', { value: true });
            stop(error);
          }, timeoutMs);
    signal?.addEventListener('abort', onAbort, { once: true });

    pendingRequests.set(requestId, {
      ...handlers,
      timeoutId,
      detachSignal: () => signal?.removeEventListener('abort', onAbort),
    });
    return true;
  }

  /**
   * How long the user has to answer the vault. The relying party's timeout
   * is only a hint the client corrects into a reasonable range (WebAuthn
   * Level 3 §5.1.3 step 4); the spec recommends 5 to 10 minutes, which also
   * gives users who need it enough time (WCAG 2.2.1). A conditional
   * (autofill) sign-in has no timeout at all: it stays available for the
   * lifetime of the page (§5.1.4.1 step 3).
   */
  function ceremonyTimeout(timeout: number | undefined, conditional: boolean): number | null {
    if (conditional) {
      return null;
    }
    if (timeout === undefined) {
      return DEFAULT_TIMEOUT_MS;
    }
    return Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, timeout));
  }

  function abortReason(signal: AbortSignal): unknown {
    return signal.reason ?? new DOMException('The operation was aborted.', 'AbortError');
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

    // id is by definition the base64url of rawId (§5.1), whatever alphabet
    // the vault happened to store the credential ID in.
    const id = arrayBufferToBase64URL(rawId);

    return onNativePrototype('PublicKeyCredential', {
      id,
      type: raw.type,
      rawId,
      response,
      authenticatorAttachment: attachment,
      getClientExtensionResults: () => extensions,
      toJSON: () => ({
        id,
        rawId: arrayBufferToBase64URL(rawId),
        type: raw.type,
        authenticatorAttachment: attachment,
        clientExtensionResults: clientExtensionResultsJSON(extensions),
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
   * Client extension outputs as the background reported them, with PRF
   * results as ArrayBuffers. Only what the background returned is exposed:
   * it reports exactly the extensions the relying party requested.
   */
  function normalizeClientExtensionResults(
    results: SerializedClientExtensionResults | null | undefined
  ): NormalizedClientExtensionResults {
    const normalized: NormalizedClientExtensionResults = {};
    if (results?.credProps) {
      normalized.credProps = { rk: results.credProps.rk === true };
    }
    if (results?.prf) {
      const prf: NonNullable<NormalizedClientExtensionResults['prf']> = {};
      if (typeof results.prf.enabled === 'boolean') {
        prf.enabled = results.prf.enabled;
      }
      if (results.prf.results?.first) {
        prf.results = { first: base64ToArrayBuffer(results.prf.results.first) };
        if (results.prf.results.second) {
          prf.results.second = base64ToArrayBuffer(results.prf.results.second);
        }
      }
      normalized.prf = prf;
    }
    return normalized;
  }

  /**
   * AuthenticationExtensionsClientOutputsJSON (WebAuthn Level 3 §5.1.8):
   * the same outputs with PRF results as base64url. Left as ArrayBuffers,
   * JSON.stringify would turn them into {} and lose them.
   */
  function clientExtensionResultsJSON(
    results: NormalizedClientExtensionResults
  ): Record<string, unknown> {
    const json: Record<string, unknown> = {};
    if (results.credProps) {
      json.credProps = { ...results.credProps };
    }
    if (results.prf) {
      const prf: Record<string, unknown> = {};
      if (results.prf.enabled !== undefined) {
        prf.enabled = results.prf.enabled;
      }
      if (results.prf.results) {
        prf.results = {
          first: arrayBufferToBase64URL(results.prf.results.first),
          ...(results.prf.results.second && {
            second: arrayBufferToBase64URL(results.prf.results.second),
          }),
        };
      }
      json.prf = prf;
    }
    return json;
  }

  /**
   * The WebIDL conversions a browser applies to the options before any
   * authenticator is involved (WebAuthn Level 3 §5.4, §5.5, §5.8). Without
   * them a page that passed, say, a string challenge or a 65-byte user.id
   * would get a passkey whose clientDataJSON or user handle its server can
   * never check, where the browser would have thrown a TypeError. Buffers
   * leave here as base64url strings: the payload reaches the background
   * through chrome.runtime.sendMessage, which Chrome serialises as JSON.
   */
  type Dictionary = Record<string, unknown>;

  function invalid(member: string, problem: string): TypeError {
    return new TypeError(`Failed to read the '${member}' property: ${problem}`);
  }

  function dictionary(value: unknown, member: string): Dictionary {
    if (value === undefined || value === null) return {};
    if (typeof value !== 'object' && typeof value !== 'function') {
      throw invalid(member, 'The provided value is not a dictionary.');
    }
    return value as Dictionary;
  }

  function required<T>(value: T | undefined, member: string): T {
    if (value === undefined) throw invalid(member, 'Required member is undefined.');
    return value;
  }

  /** DOMString: ToString, which throws for a Symbol like the bindings do. */
  function domString(value: unknown): string {
    return `${value}`;
  }

  function optionalString(value: unknown): string | undefined {
    return value === undefined ? undefined : domString(value);
  }

  /** BufferSource (ArrayBuffer or a view on one, never shared memory) as base64url. */
  function bufferSource(value: unknown, member: string): string {
    return arrayBufferToBase64URL(bufferBytes(value, member));
  }

  function bufferBytes(value: unknown, member: string): ArrayBuffer {
    if (isArrayBuffer(value)) return value.slice(0);
    if (ArrayBuffer.isView(value) && isArrayBuffer(value.buffer)) return viewToArrayBuffer(value);
    if (value === undefined) throw invalid(member, 'Required member is undefined.');
    throw invalid(member, "The provided value is not of type '(ArrayBuffer or ArrayBufferView)'.");
  }

  /** Tag check, so a buffer from another frame's realm still counts. */
  function isArrayBuffer(value: unknown): value is ArrayBuffer {
    return Object.prototype.toString.call(value) === '[object ArrayBuffer]';
  }

  function sequence<T>(
    value: unknown,
    member: string,
    item: (entry: unknown, at: string) => T
  ): T[] {
    if (
      value === null ||
      (typeof value !== 'object' && typeof value !== 'function') ||
      typeof (value as Iterable<unknown>)[Symbol.iterator] !== 'function'
    ) {
      throw invalid(member, 'The provided value cannot be converted to a sequence.');
    }
    return Array.from(value as Iterable<unknown>, (entry, index) =>
      item(entry, `${member}[${index}]`)
    );
  }

  /** WebIDL long: ToNumber, then ToInt32 with non-finite values as 0. */
  function long(value: unknown): number {
    const number = Number(value);
    return Number.isFinite(number) ? Math.trunc(number) | 0 : 0;
  }

  /** WebIDL unsigned long, used for timeout. */
  function unsignedLong(value: unknown): number | undefined {
    if (value === undefined) return undefined;
    const number = Number(value);
    return Number.isFinite(number) ? Math.trunc(number) >>> 0 : 0;
  }

  function credentialDescriptor(value: unknown, member: string) {
    const descriptor = dictionary(value, member);
    return {
      type: domString(required(descriptor.type, `${member}.type`)),
      id: bufferSource(descriptor.id, `${member}.id`),
      transports:
        descriptor.transports === undefined
          ? undefined
          : sequence(descriptor.transports, `${member}.transports`, domString),
    };
  }

  function convertCreationOptions(value: unknown) {
    const converted = convertCreationMembers(value);
    checkExtensionRules(converted.extensions, 'create', []);
    return converted;
  }

  function convertCreationMembers(value: unknown) {
    const options = dictionary(value, 'publicKey');
    const rp = dictionary(required(options.rp, 'rp'), 'rp');
    const user = dictionary(required(options.user, 'user'), 'user');
    const rpId = optionalString(rp.id);
    const userId = bufferBytes(user.id, 'user.id');
    // §5.1.3 step 5 asks for 1 to 64 bytes. Chrome enforces only the maximum,
    // and a page that works without the vault must keep working with it.
    if (userId.byteLength > 64) {
      throw new TypeError('User handle exceeds 64 bytes.');
    }
    const selection = dictionary(options.authenticatorSelection, 'authenticatorSelection');
    return {
      rp: {
        name: domString(required(rp.name, 'rp.name')),
        ...(rpId !== undefined && { id: rpId }),
      },
      // Only an absent rp.id defaults to the page host; an empty one is an
      // RP ID like any other, and an invalid one (§5.1.3 step 8).
      rpId: rpId ?? window.location.hostname,
      user: {
        id: arrayBufferToBase64URL(userId),
        name: domString(required(user.name, 'user.name')),
        displayName: domString(required(user.displayName, 'user.displayName')),
      },
      challenge: bufferSource(options.challenge, 'challenge'),
      pubKeyCredParams: sequence(
        required(options.pubKeyCredParams, 'pubKeyCredParams'),
        'pubKeyCredParams',
        (entry, at) => {
          const parameters = dictionary(entry, at);
          return {
            type: domString(required(parameters.type, `${at}.type`)),
            alg: long(required(parameters.alg, `${at}.alg`)),
          };
        }
      ),
      timeout: unsignedLong(options.timeout),
      excludeCredentials:
        options.excludeCredentials === undefined
          ? undefined
          : sequence(options.excludeCredentials, 'excludeCredentials', credentialDescriptor),
      authenticatorSelection: {
        authenticatorAttachment: optionalString(selection.authenticatorAttachment),
        residentKey: optionalString(selection.residentKey),
        requireResidentKey: Boolean(selection.requireResidentKey),
        userVerification: optionalString(selection.userVerification),
      },
      hints: options.hints === undefined ? undefined : sequence(options.hints, 'hints', domString),
      attestation: optionalString(options.attestation),
      extensions: convertExtensions(options.extensions),
    };
  }

  function convertRequestOptions(value: unknown) {
    const converted = convertRequestMembers(value);
    checkExtensionRules(
      converted.extensions,
      'get',
      (converted.allowCredentials ?? []).map((descriptor) => descriptor.id)
    );
    return converted;
  }

  function convertRequestMembers(value: unknown) {
    const options = dictionary(value, 'publicKey');
    return {
      rpId: optionalString(options.rpId) ?? window.location.hostname,
      challenge: bufferSource(options.challenge, 'challenge'),
      timeout: unsignedLong(options.timeout),
      allowCredentials:
        options.allowCredentials === undefined
          ? undefined
          : sequence(options.allowCredentials, 'allowCredentials', credentialDescriptor),
      userVerification: optionalString(options.userVerification),
      hints: options.hints === undefined ? undefined : sequence(options.hints, 'hints', domString),
      extensions: convertExtensions(options.extensions),
    };
  }

  /**
   * Only the extensions the vault implements are passed on, PRF salts as
   * base64url like every other buffer. The browser likewise reads only the
   * extensions it knows, so an exotic value under some other name cannot
   * fail the call.
   */
  function convertExtensions(value: unknown): Dictionary | undefined {
    if (value === undefined || value === null) {
      return undefined;
    }
    const extensions = dictionary(value, 'extensions');
    const converted: Dictionary = {};
    if (extensions.credProps !== undefined) {
      converted.credProps = Boolean(extensions.credProps);
    }
    if (extensions.prf !== undefined) {
      const prf = dictionary(extensions.prf, 'extensions.prf');
      const inputs: Dictionary = {};
      if (prf.eval !== undefined) {
        inputs.eval = convertPrfValues(prf.eval, 'extensions.prf.eval');
      }
      if (prf.evalByCredential !== undefined) {
        const record = dictionary(prf.evalByCredential, 'extensions.prf.evalByCredential');
        const byCredential: Dictionary = {};
        for (const credentialId of Object.keys(record)) {
          byCredential[credentialId] = convertPrfValues(
            record[credentialId],
            `extensions.prf.evalByCredential.${credentialId}`
          );
        }
        inputs.evalByCredential = byCredential;
      }
      converted.prf = inputs;
    }
    return converted;
  }

  /**
   * The rules Chrome enforces for the extensions the vault implements, with
   * the errors Chrome throws, checked once the options are converted:
   *
   *   credProps   registration only (NotSupportedError at sign-in)
   *   prf         evalByCredential is sign-in only (NotSupportedError at
   *               registration), needs a non-empty allowCredentials
   *               (NotSupportedError), and each key must be the unpadded
   *               base64url of one of those credential IDs (SyntaxError),
   *               WebAuthn Level 3 §10.1.4
   */
  function checkExtensionRules(
    extensions: Dictionary | undefined,
    ceremony: 'create' | 'get',
    allowedIds: string[]
  ): void {
    if (!extensions) return;
    if (ceremony === 'get' && extensions.credProps) {
      throw new DOMException(
        "The 'credProps' extension is only valid when creating a credential",
        'NotSupportedError'
      );
    }
    const byCredential = (extensions.prf as Dictionary | undefined)?.evalByCredential as
      | Dictionary
      | undefined;
    if (byCredential === undefined) return;
    if (ceremony === 'create') {
      throw new DOMException(
        "The 'evalByCredential' field cannot be set when creating a credential.",
        'NotSupportedError'
      );
    }
    const keys = Object.keys(byCredential);
    if (keys.length > 0 && allowedIds.length === 0) {
      throw new DOMException(
        "'prf' extension has 'evalByCredential' with an empty allow list",
        'NotSupportedError'
      );
    }
    for (const key of keys) {
      if (!/^[A-Za-z0-9_-]+$/.test(key) || key.length % 4 === 1) {
        throw new DOMException(
          "'prf' extension contains invalid base64url data in 'evalByCredential'",
          'SyntaxError'
        );
      }
      if (!allowedIds.includes(arrayBufferToBase64URL(base64ToArrayBuffer(key)))) {
        throw new DOMException(
          "'prf' extension contains 'evalByCredential' key that doesn't match any in allowCredentials",
          'SyntaxError'
        );
      }
    }
  }

  function convertPrfValues(value: unknown, member: string): { first: string; second?: string } {
    const values = dictionary(value, member);
    return {
      first: bufferSource(values.first, `${member}.first`),
      ...(values.second !== undefined && {
        second: bufferSource(values.second, `${member}.second`),
      }),
    };
  }

  /**
   * Copy out just the bytes a view covers. A view's `.buffer` is the whole
   * backing store, so `subarray()` or a pooled buffer would otherwise leak
   * neighbouring bytes into the challenge, user ID or credential IDs.
   */
  function viewToArrayBuffer(view: ArrayBufferView): ArrayBuffer {
    return (view.buffer as ArrayBuffer).slice(view.byteOffset, view.byteOffset + view.byteLength);
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
    // Handle any ArrayBufferView (Uint8Array, DataView, ...)
    if (ArrayBuffer.isView(base64url)) {
      return viewToArrayBuffer(base64url);
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
