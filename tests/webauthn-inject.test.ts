/**
 * The page-world shim must hand sites objects that pass for the browser's own
 * PublicKeyCredential / AuthenticatorAttestationResponse /
 * AuthenticatorAssertionResponse. Some relying parties branch on `instanceof`
 * and on the Level 3 helper methods (issue #8).
 *
 * The native classes are stubbed the way a browser implements them: every
 * prototype member throws "Illegal invocation" unless the receiver is a real
 * platform object. That is exactly what a bare prototype swap trips over, so
 * the tests here catch a half fix as well as the original bug.
 */

function illegal(): TypeError {
  return new TypeError('Illegal invocation');
}

function tag(ctor: Function, name: string): void {
  Object.defineProperty(ctor.prototype, Symbol.toStringTag, { value: name, configurable: true });
}

class FakeCredential {
  get id(): string {
    throw illegal();
  }
  get type(): string {
    throw illegal();
  }
}
tag(FakeCredential, 'Credential');

class FakePublicKeyCredential extends FakeCredential {
  get rawId(): ArrayBuffer {
    throw illegal();
  }
  get response(): unknown {
    throw illegal();
  }
  get authenticatorAttachment(): string | null {
    throw illegal();
  }
  getClientExtensionResults(): unknown {
    throw illegal();
  }
  toJSON(): unknown {
    throw illegal();
  }
}
tag(FakePublicKeyCredential, 'PublicKeyCredential');

class FakeAuthenticatorResponse {
  get clientDataJSON(): ArrayBuffer {
    throw illegal();
  }
}
tag(FakeAuthenticatorResponse, 'AuthenticatorResponse');

class FakeAttestationResponse extends FakeAuthenticatorResponse {
  get attestationObject(): ArrayBuffer {
    throw illegal();
  }
  getTransports(): string[] {
    throw illegal();
  }
  getAuthenticatorData(): ArrayBuffer {
    throw illegal();
  }
  getPublicKey(): ArrayBuffer | null {
    throw illegal();
  }
  getPublicKeyAlgorithm(): number {
    throw illegal();
  }
}
tag(FakeAttestationResponse, 'AuthenticatorAttestationResponse');

class FakeAssertionResponse extends FakeAuthenticatorResponse {
  get authenticatorData(): ArrayBuffer {
    throw illegal();
  }
  get signature(): ArrayBuffer {
    throw illegal();
  }
  get userHandle(): ArrayBuffer | null {
    throw illegal();
  }
}
tag(FakeAssertionResponse, 'AuthenticatorAssertionResponse');

const g = globalThis as Record<string, unknown>;
g.PublicKeyCredential = FakePublicKeyCredential;
g.AuthenticatorAttestationResponse = FakeAttestationResponse;
g.AuthenticatorAssertionResponse = FakeAssertionResponse;

// Side-effect import: hooks navigator.credentials and listens for responses.
require('../src/content/webauthn-inject');

const PAGE_SOURCE = 'PASSKEY_VAULT_PAGE';
const CONTENT_SOURCE = 'PASSKEY_VAULT_CONTENT';
const COSE_ES256 = -7;

const CLIENT_DATA = new Uint8Array([1, 2, 3]);
const ATTESTATION = new Uint8Array([4, 5, 6, 7]);
const AUTH_DATA = new Uint8Array([8, 9]);
const PUBLIC_KEY = new Uint8Array([10, 11, 12]);
const SIGNATURE = new Uint8Array([13, 14]);
const USER_HANDLE = new Uint8Array([15]);
const RAW_ID = new Uint8Array([16, 17, 18, 19]);

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function bytesOf(buffer: ArrayBuffer): number[] {
  return Array.from(new Uint8Array(buffer));
}

/** Wait for the shim to post its request, then answer it as the content script would. */
function nextRequestId(): Promise<string> {
  return new Promise((resolve) => {
    const listener = (event: MessageEvent) => {
      if (event.data?.source !== PAGE_SOURCE) {
        return;
      }
      window.removeEventListener('message', listener);
      resolve(event.data.requestId);
    };
    window.addEventListener('message', listener);
  });
}

function answer(requestId: string, credential: unknown): void {
  window.dispatchEvent(
    new MessageEvent('message', {
      data: { source: CONTENT_SOURCE, requestId, result: { success: true, credential } },
      source: window,
    })
  );
}

function createPayload() {
  return {
    id: b64url(RAW_ID),
    rawId: b64(RAW_ID),
    type: 'public-key',
    response: {
      clientDataJSON: b64(CLIENT_DATA),
      attestationObject: b64(ATTESTATION),
      authenticatorData: b64(AUTH_DATA),
      publicKey: b64(PUBLIC_KEY),
      publicKeyAlgorithm: COSE_ES256,
      transports: ['internal'],
    },
    authenticatorAttachment: 'platform',
    clientExtensionResults: {},
  };
}

function getPayload(userHandle: string | null) {
  return {
    id: b64url(RAW_ID),
    rawId: b64(RAW_ID),
    type: 'public-key',
    response: {
      clientDataJSON: b64(CLIENT_DATA),
      authenticatorData: b64(AUTH_DATA),
      signature: b64(SIGNATURE),
      userHandle,
    },
    authenticatorAttachment: 'cross-platform',
    clientExtensionResults: {},
  };
}

async function runCreate(payload = createPayload()): Promise<any> {
  const pending = nextRequestId();
  const result = navigator.credentials.create({
    publicKey: {
      rp: { name: 'Example' },
      user: { id: new Uint8Array([1]), name: 'a', displayName: 'a' },
      challenge: new Uint8Array([9]),
      pubKeyCredParams: [{ type: 'public-key', alg: COSE_ES256 }],
    },
  });
  answer(await pending, payload);
  return result;
}

async function runGet(payload = getPayload(b64(USER_HANDLE))): Promise<any> {
  const pending = nextRequestId();
  const result = navigator.credentials.get({
    publicKey: { challenge: new Uint8Array([9]) },
  });
  answer(await pending, payload);
  return result;
}

/**
 * Touch every member the native prototype chain defines. A synthetic object
 * that forgets to shadow one lets the call fall through to the stub, which
 * throws "Illegal invocation" just like the browser would.
 */
function touchAllNativeMembers(obj: object): void {
  let proto = Object.getPrototypeOf(obj);
  while (proto && proto !== Object.prototype) {
    for (const name of Object.getOwnPropertyNames(proto)) {
      if (name === 'constructor') {
        continue;
      }
      const value = (obj as Record<string, unknown>)[name];
      if (typeof value === 'function') {
        (value as Function).call(obj);
      }
    }
    proto = Object.getPrototypeOf(proto);
  }
}

describe('webauthn-inject credential shape', () => {
  describe('create()', () => {
    it('returns a PublicKeyCredential holding an AuthenticatorAttestationResponse', async () => {
      const cred = await runCreate();

      expect(cred).toBeInstanceOf(FakePublicKeyCredential);
      expect(cred.response).toBeInstanceOf(FakeAttestationResponse);
      expect(cred.response).not.toBeInstanceOf(FakeAssertionResponse);
      expect(Object.prototype.toString.call(cred)).toBe('[object PublicKeyCredential]');
      expect(Object.prototype.toString.call(cred.response)).toBe(
        '[object AuthenticatorAttestationResponse]'
      );
    });

    it('exposes the spec fields as own data', async () => {
      const cred = await runCreate();

      expect(cred.id).toBe(b64url(RAW_ID));
      expect(cred.type).toBe('public-key');
      expect(cred.authenticatorAttachment).toBe('platform');
      expect(bytesOf(cred.rawId)).toEqual(Array.from(RAW_ID));
      expect(bytesOf(cred.response.clientDataJSON)).toEqual(Array.from(CLIENT_DATA));
      expect(bytesOf(cred.response.attestationObject)).toEqual(Array.from(ATTESTATION));
    });

    it('implements the Level 3 attestation helpers', async () => {
      const cred = await runCreate();

      expect(cred.response.getTransports()).toEqual(['internal']);
      expect(bytesOf(cred.response.getAuthenticatorData())).toEqual(Array.from(AUTH_DATA));
      expect(bytesOf(cred.response.getPublicKey())).toEqual(Array.from(PUBLIC_KEY));
      expect(cred.response.getPublicKeyAlgorithm()).toBe(COSE_ES256);
      expect(cred.getClientExtensionResults()).toEqual({ credProps: { rk: true } });
    });

    it('never falls through to a native member', async () => {
      const cred = await runCreate();

      expect(() => touchAllNativeMembers(cred)).not.toThrow();
      expect(() => touchAllNativeMembers(cred.response)).not.toThrow();
    });

    it('serialises as RegistrationResponseJSON', async () => {
      const cred = await runCreate();

      expect(cred.toJSON()).toEqual({
        id: b64url(RAW_ID),
        rawId: b64url(RAW_ID),
        type: 'public-key',
        authenticatorAttachment: 'platform',
        clientExtensionResults: { credProps: { rk: true } },
        response: {
          clientDataJSON: b64url(CLIENT_DATA),
          attestationObject: b64url(ATTESTATION),
          authenticatorData: b64url(AUTH_DATA),
          publicKey: b64url(PUBLIC_KEY),
          publicKeyAlgorithm: COSE_ES256,
          transports: ['internal'],
        },
      });
    });
  });

  describe('get()', () => {
    it('returns a PublicKeyCredential holding an AuthenticatorAssertionResponse', async () => {
      const cred = await runGet();

      expect(cred).toBeInstanceOf(FakePublicKeyCredential);
      expect(cred.response).toBeInstanceOf(FakeAssertionResponse);
      expect(cred.response).not.toBeInstanceOf(FakeAttestationResponse);
      expect(Object.prototype.toString.call(cred.response)).toBe(
        '[object AuthenticatorAssertionResponse]'
      );
    });

    it('exposes the assertion fields as own data', async () => {
      const cred = await runGet();

      expect(bytesOf(cred.response.clientDataJSON)).toEqual(Array.from(CLIENT_DATA));
      expect(bytesOf(cred.response.authenticatorData)).toEqual(Array.from(AUTH_DATA));
      expect(bytesOf(cred.response.signature)).toEqual(Array.from(SIGNATURE));
      expect(bytesOf(cred.response.userHandle)).toEqual(Array.from(USER_HANDLE));
    });

    it('keeps a missing userHandle null on the response and omits it from JSON', async () => {
      const cred = await runGet(getPayload(null));

      expect(cred.response.userHandle).toBeNull();
      expect(cred.toJSON().response).not.toHaveProperty('userHandle');
      expect(JSON.parse(JSON.stringify(cred)).response).not.toHaveProperty('userHandle');
    });

    it('never falls through to a native member', async () => {
      const cred = await runGet();

      expect(() => touchAllNativeMembers(cred)).not.toThrow();
      expect(() => touchAllNativeMembers(cred.response)).not.toThrow();
    });

    it('serialises as AuthenticationResponseJSON', async () => {
      const cred = await runGet();

      expect(cred.toJSON()).toEqual({
        id: b64url(RAW_ID),
        rawId: b64url(RAW_ID),
        type: 'public-key',
        authenticatorAttachment: 'cross-platform',
        clientExtensionResults: { credProps: { rk: true } },
        response: {
          clientDataJSON: b64url(CLIENT_DATA),
          authenticatorData: b64url(AUTH_DATA),
          signature: b64url(SIGNATURE),
          userHandle: b64url(USER_HANDLE),
        },
      });
    });
  });
});
