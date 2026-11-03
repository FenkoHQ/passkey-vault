/**
 * Stand-ins for the browser's WebAuthn classes and native authenticator.
 *
 * Every prototype member throws "Illegal invocation" unless the receiver is a
 * real platform object, exactly as Chrome's bindings do. A credential the
 * vault builds therefore only works if it shadows every member, and
 * `instanceof` checks behave as they would on a real page.
 *
 * Must be installed before src/content/webauthn-inject.ts loads: the shim
 * captures navigator.credentials.create/get once, at load.
 */

function illegal(): TypeError {
  return new TypeError('Illegal invocation');
}

function tag(ctor: { prototype: object }, name: string): void {
  Object.defineProperty(ctor.prototype, Symbol.toStringTag, { value: name, configurable: true });
}

export class FakeCredential {
  get id(): string {
    throw illegal();
  }
  get type(): string {
    throw illegal();
  }
}
tag(FakeCredential, 'Credential');

export class FakePublicKeyCredential extends FakeCredential {
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

export class FakeAuthenticatorResponse {
  get clientDataJSON(): ArrayBuffer {
    throw illegal();
  }
}
tag(FakeAuthenticatorResponse, 'AuthenticatorResponse');

export class FakeAttestationResponse extends FakeAuthenticatorResponse {
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

export class FakeAssertionResponse extends FakeAuthenticatorResponse {
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

export interface NativeAuthenticator {
  create: jest.Mock;
  get: jest.Mock;
  /** Forget calls and answers set by a test; back to the dismissed prompt. */
  reset(): void;
}

/**
 * Install the classes on the page global and a native navigator.credentials
 * whose create/get record their calls. The default native answer is the one
 * a browser with no matching authenticator gives after the user dismisses
 * its prompt.
 */
export function installNativeWebAuthn(): NativeAuthenticator {
  const g = globalThis as Record<string, unknown>;
  g.Credential = FakeCredential;
  g.PublicKeyCredential = FakePublicKeyCredential;
  g.AuthenticatorResponse = FakeAuthenticatorResponse;
  g.AuthenticatorAttestationResponse = FakeAttestationResponse;
  g.AuthenticatorAssertionResponse = FakeAssertionResponse;

  const dismissed = () =>
    Promise.reject(
      new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError')
    );
  const native: NativeAuthenticator = {
    create: jest.fn(dismissed),
    get: jest.fn(dismissed),
    reset() {
      native.create.mockReset().mockImplementation(dismissed);
      native.get.mockReset().mockImplementation(dismissed);
    },
  };
  const credentials = {
    create: (...args: unknown[]) => native.create(...args),
    get: (...args: unknown[]) => native.get(...args),
    store: jest.fn(),
    preventSilentAccess: jest.fn(),
  };
  Object.defineProperty(globalThis, 'navigator', {
    value: {
      ...(globalThis.navigator || {}),
      credentials,
      language: 'en-US',
      platform: 'Linux x86_64',
    },
    writable: true,
    configurable: true,
  });
  return native;
}
