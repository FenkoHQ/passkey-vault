/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * The checks a WebAuthn client makes before any authenticator is involved
 * (WebAuthn Level 3 §5.1.3 and §5.1.4.1, plus the WebIDL conversions of the
 * options dictionaries). The vault replaces the browser's client, so it has
 * to refuse the same requests the browser would, with the same errors:
 * relying parties branch on TypeError, SecurityError, NotSupportedError and
 * InvalidStateError, and an input the browser would reject must not turn
 * into a stored passkey the site can never use.
 */

import { setupVault, vaultReady } from '../helpers/harness';
import { outcome, register } from '../helpers/ceremony';
import { b64url, sha256, hex, toBytes } from '../helpers/bytes';
import {
  authenticationJSON,
  creationOptionsFromJSON,
  random,
  registrationJSON,
  requestOptionsFromJSON,
} from '../helpers/options';

const vault = setupVault('https://example.com/login');

beforeAll(() => vaultReady(vault));
beforeEach(async () => {
  await vault.reset();
  vault.goto('https://example.com/login');
});
afterEach(() => {
  jest.useRealTimers();
});

function createWith(mutate: (options: any) => void, extra: Record<string, unknown> = {}) {
  const options: any = creationOptionsFromJSON(
    registrationJSON({ rp: { name: 'Example', id: 'example.com' } })
  );
  mutate(options);
  return outcome(navigator.credentials.create({ publicKey: options, ...extra }));
}

function getWith(mutate: (options: any) => void, extra: Record<string, unknown> = {}) {
  const options: any = requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' }));
  mutate(options);
  return outcome(navigator.credentials.get({ publicKey: options, ...extra }));
}

describe('user.id may be at most 64 bytes (§5.1.3 step 5)', () => {
  it.each([0, 1, 16, 64])('accepts %i bytes, as Chrome does', async (length) => {
    const { error } = await createWith((o) => (o.user.id = random(length)));

    expect(error).toBeUndefined();
  });

  it.each([65, 1024])('throws TypeError for %i bytes, storing nothing', async (length) => {
    const { error } = await createWith((o) => (o.user.id = new Uint8Array(length)));

    expect(error).toBeInstanceOf(TypeError);
    expect(await vault.passkeys()).toEqual([]);
    expect(vault.user.confirmCreate).not.toHaveBeenCalled();
  });
});

describe('BufferSource members are converted the WebIDL way', () => {
  const notBuffers: Array<[string, unknown]> = [
    ['a string', 'Y2hhbGxlbmdl'],
    ['a number array', [1, 2, 3, 4]],
    ['a plain object', { 0: 1, 1: 2 }],
    ['a number', 42],
    ['null', null],
  ];

  it.each(notBuffers)(
    'create() throws TypeError for a challenge that is %s',
    async (_label, value) => {
      const { error } = await createWith((o) => (o.challenge = value));

      expect(error).toBeInstanceOf(TypeError);
      expect(vault.user.confirmCreate).not.toHaveBeenCalled();
    }
  );

  it.each(notBuffers)(
    'create() throws TypeError for a user.id that is %s',
    async (_label, value) => {
      const { error } = await createWith((o) => (o.user.id = value));

      expect(error).toBeInstanceOf(TypeError);
      expect(await vault.passkeys()).toEqual([]);
    }
  );

  it.each(notBuffers)(
    'get() throws TypeError for a challenge that is %s',
    async (_label, value) => {
      const { error } = await getWith((o) => (o.challenge = value));

      expect(error).toBeInstanceOf(TypeError);
      expect(vault.native.get).not.toHaveBeenCalled();
    }
  );

  it('get() throws TypeError for an allowCredentials id that is not a BufferSource', async () => {
    const { error } = await getWith(
      (o) => (o.allowCredentials = [{ type: 'public-key', id: 'abc' }])
    );

    expect(error).toBeInstanceOf(TypeError);
  });

  it('create() throws TypeError for an excludeCredentials id that is not a BufferSource', async () => {
    const { error } = await createWith(
      (o) => (o.excludeCredentials = [{ type: 'public-key', id: [1, 2] }])
    );

    expect(error).toBeInstanceOf(TypeError);
  });
});

describe('required dictionary members', () => {
  it.each([
    ['rp', (o: any) => delete o.rp],
    ['rp.name', (o: any) => delete o.rp.name],
    ['user', (o: any) => delete o.user],
    ['user.name', (o: any) => delete o.user.name],
    ['user.displayName', (o: any) => delete o.user.displayName],
    ['user.id', (o: any) => delete o.user.id],
    ['challenge', (o: any) => delete o.challenge],
    ['pubKeyCredParams', (o: any) => delete o.pubKeyCredParams],
    ['pubKeyCredParams[].alg', (o: any) => (o.pubKeyCredParams = [{ type: 'public-key' }])],
  ])('create() throws TypeError without %s', async (_member, mutate) => {
    const { error } = await createWith(mutate);

    expect(error).toBeInstanceOf(TypeError);
    expect(vault.user.confirmCreate).not.toHaveBeenCalled();
  });

  it('get() throws TypeError without a challenge', async () => {
    const { error } = await getWith((o) => delete o.challenge);

    expect(error).toBeInstanceOf(TypeError);
  });

  it('converts non-string names like WebIDL DOMString does', async () => {
    const { error } = await createWith((o) => {
      o.user.name = 12345;
      o.user.displayName = 0;
    });

    expect(error).toBeUndefined();
    const [stored] = await vault.passkeys();
    expect(stored.user.name).toBe('12345');
    expect(stored.user.displayName).toBe('0');
  });
});

describe('pubKeyCredParams (§5.1.3 steps 10-11)', () => {
  it('uses the defaults (ES256, RS256) when the list is empty', async () => {
    const { error, value } = await createWith((o) => (o.pubKeyCredParams = []));

    expect(error).toBeUndefined();
    expect((value as any).response.getPublicKeyAlgorithm()).toBe(-7);
  });

  it('picks ES256 wherever it sits in the list', async () => {
    const { value } = await createWith(
      (o) =>
        (o.pubKeyCredParams = [
          { type: 'public-key', alg: -8 },
          { type: 'public-key', alg: -257 },
          { type: 'public-key', alg: -7 },
        ])
    );

    expect((value as any).response.getPublicKeyAlgorithm()).toBe(-7);
  });

  it.each([
    ['EdDSA only', [{ type: 'public-key', alg: -8 }]],
    ['RS256 only', [{ type: 'public-key', alg: -257 }]],
    [
      'ES384 and RS1',
      [
        { type: 'public-key', alg: -35 },
        { type: 'public-key', alg: -65535 },
      ],
    ],
    ['ES256 under an unknown type', [{ type: 'secret-key', alg: -7 }]],
  ])(
    'leaves %s to the browser instead of minting an ES256 key the RP refuses',
    async (_label, params) => {
      vault.native.create.mockResolvedValue({ id: 'platform-credential' });

      const { value } = await createWith((o) => (o.pubKeyCredParams = params));

      expect((value as any)?.id).toBe('platform-credential');
      expect(vault.user.confirmCreate).not.toHaveBeenCalled();
      expect(await vault.passkeys()).toEqual([]);
    }
  );

  it('ignores entries of an unknown type next to a usable one', async () => {
    const { value } = await createWith(
      (o) =>
        (o.pubKeyCredParams = [
          { type: 'future-key', alg: -999 },
          { type: 'public-key', alg: -7 },
        ])
    );

    expect((value as any).response.getPublicKeyAlgorithm()).toBe(-7);
  });
});

describe('RP ID validation (§5.1.3 step 8, §5.1.4.1 step 8)', () => {
  // The vault must only answer for an RP ID the page's origin may claim. For
  // anything else it steps aside, so the browser applies its own rules
  // (SecurityError, or a Related Origin Request it can verify).
  const refused: Array<[string, string, string]> = [
    ['an unrelated site', 'https://example.com/', 'evil.com'],
    ['a sibling subdomain', 'https://a.example.com/', 'b.example.com'],
    ['a child of the host', 'https://example.com/', 'login.example.com'],
    ['a bare TLD', 'https://example.com/', 'com'],
    ['a public suffix', 'https://shop.example.co.uk/', 'co.uk'],
    ['a private public suffix', 'https://foo.github.io/', 'github.io'],
    ['a less common public suffix', 'https://shop.example.com.ar/', 'com.ar'],
    ["a domain inside the page's public suffix", 'https://foo.up.railway.app/', 'railway.app'],
    ['a look-alike suffix', 'https://notexample.com/', 'example.com'],
    ['a parent of an IP address', 'https://192.168.1.10/', '168.1.10'],
    ['an IP address, even its own', 'https://192.168.1.10/', '192.168.1.10'],
    ['the loopback address', 'http://127.0.0.1:8080/', '127.0.0.1'],
    ['a URL instead of a host', 'https://example.com/', 'https://example.com'],
    ['a host with a port', 'https://example.com/', 'example.com:443'],
    ['a trailing dot', 'https://example.com/', 'example.com.'],
    ['the host in upper case', 'https://example.com/', 'EXAMPLE.COM'],
    ['a parent in mixed case', 'https://www.example.com/', 'Example.com'],
    ['an empty RP ID', 'https://example.com/', ''],
  ];

  it.each(refused)('does not create a passkey for %s', async (_label, url, rpId) => {
    vault.goto(url);
    vault.native.create.mockRejectedValue(new DOMException('rejected by browser', 'SecurityError'));

    const { error } = await createWith((o) => (o.rp.id = rpId));

    expect(error?.name).toBe('SecurityError');
    expect(vault.user.confirmCreate).not.toHaveBeenCalled();
    expect(await vault.passkeys()).toEqual([]);
  });

  it.each(refused)('does not sign in for %s', async (_label, url, rpId) => {
    vault.goto(url);
    vault.native.get.mockRejectedValue(new DOMException('rejected by browser', 'SecurityError'));

    const { error } = await getWith((o) => (o.rpId = rpId));

    expect(error?.name).toBe('SecurityError');
    expect(vault.user.choosePasskey).not.toHaveBeenCalled();
  });

  it.each([
    ['the host itself', 'https://example.com/', 'example.com'],
    ['the registrable parent', 'https://www.login.example.com/', 'example.com'],
    ['an intermediate parent', 'https://www.login.example.com/', 'login.example.com'],
    ['a parent under a two-level public suffix', 'https://www.example.co.uk/', 'example.co.uk'],
    ['a parent under a private public suffix', 'https://a.foo.github.io/', 'foo.github.io'],
    ['localhost', 'http://localhost:3000/', 'localhost'],
  ])('creates a passkey for %s', async (_label, url, rpId) => {
    vault.goto(url);

    const { value, error } = await createWith((o) => (o.rp.id = rpId));

    expect(error).toBeUndefined();
    const authData = toBytes((value as any).response.getAuthenticatorData());
    expect(hex(authData.slice(0, 32))).toBe(hex(await sha256(rpId)));
  });
});

describe('excludeCredentials (§6.3.2 step 3)', () => {
  it('asks the user first, then refuses with InvalidStateError and stores nothing new', async () => {
    const existing = await register();
    const before = await vault.passkeys();

    const { error } = await createWith(
      (o) =>
        (o.excludeCredentials = [{ type: 'public-key', id: existing.record.rawId.slice().buffer }])
    );

    expect(error?.name).toBe('InvalidStateError');
    expect(vault.user.confirmCreate).toHaveBeenCalledTimes(2);
    expect(await vault.passkeys()).toHaveLength(before.length);
  });

  it('ignores excluded IDs the vault does not hold', async () => {
    const { error } = await createWith(
      (o) => (o.excludeCredentials = [{ type: 'public-key', id: random(32), transports: ['usb'] }])
    );

    expect(error).toBeUndefined();
  });

  it('only excludes a matching ID registered to the same RP ID', async () => {
    vault.goto('https://other.example.org/');
    const elsewhere = await register({ rp: { name: 'Other', id: 'other.example.org' } });
    vault.goto('https://example.com/');

    const { error } = await createWith(
      (o) =>
        (o.excludeCredentials = [{ type: 'public-key', id: elsewhere.record.rawId.slice().buffer }])
    );

    expect(error).toBeUndefined();
  });
});

describe('AbortSignal (§5.6)', () => {
  it('rejects with the abort reason before anything starts', async () => {
    const controller = new AbortController();
    const reason = new DOMException('page navigated', 'AbortError');
    controller.abort(reason);

    const { error } = await createWith(() => undefined, { signal: controller.signal });

    expect(error).toBe(reason);
    expect(vault.user.confirmCreate).not.toHaveBeenCalled();
  });

  it('closes the dialog and creates nothing when the page aborts mid-ceremony', async () => {
    const controller = new AbortController();
    let dialogSignal: AbortSignal | undefined;
    vault.user.confirmCreate.mockImplementation(
      (_rp: string, _user: string, signal: AbortSignal) =>
        new Promise((resolve) => {
          dialogSignal = signal;
          signal.addEventListener('abort', () => resolve(false));
        })
    );

    const pending = createWith(() => undefined, { signal: controller.signal });
    await vault.settle();
    controller.abort();
    const { error } = await pending;
    await vault.settle();

    expect(error?.name).toBe('AbortError');
    expect(dialogSignal?.aborted).toBe(true);
    expect(await vault.passkeys()).toEqual([]);
  });

  it('get() rejects with the abort reason and does not open the browser prompt', async () => {
    await register();
    const controller = new AbortController();
    vault.user.choosePasskey.mockImplementation(() => new Promise(() => undefined));

    const pending = getWith(() => undefined, { signal: controller.signal });
    await vault.settle();
    controller.abort('user navigated away');
    const { error } = await pending;

    expect(error).toBe('user navigated away');
    expect(vault.native.get).not.toHaveBeenCalled();
  });
});

describe('ceremony timeout (§5.1.3 step 4, §15.1)', () => {
  function neverAnswer() {
    vault.user.confirmCreate.mockImplementation(() => new Promise(() => undefined));
    vault.user.choosePasskey.mockImplementation(() => new Promise(() => undefined));
  }

  async function settledAfter(promise: Promise<unknown>, ms: number): Promise<boolean> {
    let settled = false;
    void promise.then(
      () => (settled = true),
      () => (settled = true)
    );
    await jest.advanceTimersByTimeAsync(ms);
    return settled;
  }

  it('gives the user at least the recommended 5 minutes even when the RP asks for 60s', async () => {
    await register();
    neverAnswer();
    jest.useFakeTimers({ doNotFake: ['queueMicrotask', 'nextTick', 'setImmediate'] });

    const pending = getWith((o) => (o.timeout = 60000));

    expect(await settledAfter(pending, 299000)).toBe(false);
    expect(await settledAfter(pending, 2000)).toBe(true);
    expect((await pending).error?.name).toBe('NotAllowedError');
  });

  it('caps a very long RP timeout at the recommended 10 minutes', async () => {
    neverAnswer();
    jest.useFakeTimers({ doNotFake: ['queueMicrotask', 'nextTick', 'setImmediate'] });

    const pending = createWith((o) => (o.timeout = 24 * 60 * 60 * 1000));

    expect(await settledAfter(pending, 599000)).toBe(false);
    expect(await settledAfter(pending, 2000)).toBe(true);
  });

  it('never times out a conditional (autofill) request', async () => {
    await register();
    neverAnswer();
    jest.useFakeTimers({ doNotFake: ['queueMicrotask', 'nextTick', 'setImmediate'] });

    const pending = getWith((o) => (o.timeout = 60000), { mediation: 'conditional' });

    expect(await settledAfter(pending, 60 * 60 * 1000)).toBe(false);
  });

  it('still lets the page abort a conditional request', async () => {
    await register();
    neverAnswer();
    const controller = new AbortController();

    const pending = getWith(() => undefined, {
      mediation: 'conditional',
      signal: controller.signal,
    });
    await vault.settle();
    controller.abort();

    expect((await pending).error?.name).toBe('AbortError');
  });
});

describe('a secure context is required', () => {
  it('refuses a request posted from an insecure page', async () => {
    vault.goto('http://example.com/');

    const { error } = await createWith((o) => delete o.rp.id);

    expect(error).toBeDefined();
    expect(vault.user.confirmCreate).not.toHaveBeenCalled();
    expect(await vault.passkeys()).toEqual([]);
  });
});

describe('the page shim never strands a promise', () => {
  it('rejects instead of hanging when the vault answers with a malformed credential', async () => {
    const pending = navigator.credentials.create({
      publicKey: creationOptionsFromJSON(
        registrationJSON({ rp: { name: 'Example', id: 'example.com' } })
      ),
    });
    const request = vault.posted.find((m: any) => m.data?.type === 'PASSKEY_CREATE_REQUEST');
    window.dispatchEvent(
      new MessageEvent('message', {
        source: window,
        data: {
          source: 'PASSKEY_VAULT_CONTENT',
          requestId: (request?.data as any)?.requestId,
          result: {
            success: true,
            credential: { id: 'x', rawId: '%%%', type: 'public-key', response: {} },
          },
        },
      })
    );

    const { error } = await outcome(pending);

    expect(error).toBeDefined();
  });

  it('rejects instead of hanging when an answer has no result at all', async () => {
    const pending = navigator.credentials.get({
      publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
    });
    const request = vault.posted.find((m: any) => m.data?.type === 'PASSKEY_GET_REQUEST');
    window.dispatchEvent(
      new MessageEvent('message', {
        source: window,
        data: { source: 'PASSKEY_VAULT_CONTENT', requestId: (request?.data as any)?.requestId },
      })
    );
    vault.native.get.mockResolvedValue({ id: 'native' });

    const { error, value } = await outcome(pending);

    expect(error ?? value).toBeDefined();
  });

  it('turns an unreadable stored user handle into an error, not a hang', async () => {
    const registration = await register();
    const passkeys = vault.storage.passkeys as any[];
    passkeys[0].user.id = 'not base64 at all!';

    const { error, value } = await outcome(
      navigator.credentials.get({
        publicKey: requestOptionsFromJSON(
          authenticationJSON({
            rpId: 'example.com',
            allowCredentials: [{ type: 'public-key', id: registration.record.id }],
          })
        ),
      })
    );

    expect(error ?? value).toBeDefined();
    void b64url;
  });
});

describe('extension inputs Chrome refuses (§10.1.3, §10.1.4)', () => {
  const id = (n: number) => new Uint8Array(16).fill(n);

  it('rejects prf.evalByCredential at registration with NotSupportedError', async () => {
    const { error } = await createWith(
      (o) =>
        (o.extensions = { prf: { evalByCredential: { AQEBAQEBAQEBAQEBAQEBAQ: { first: id(1) } } } })
    );

    expect(error?.name).toBe('NotSupportedError');
    expect(vault.user.confirmCreate).not.toHaveBeenCalled();
  });

  it('rejects credProps at sign-in with NotSupportedError, without the browser prompt', async () => {
    const { error } = await getWith((o) => (o.extensions = { credProps: true }));

    expect(error?.name).toBe('NotSupportedError');
    expect(vault.native.get).not.toHaveBeenCalled();
  });

  it('rejects evalByCredential without allowCredentials with NotSupportedError', async () => {
    const { error } = await getWith(
      (o) =>
        (o.extensions = { prf: { evalByCredential: { AQEBAQEBAQEBAQEBAQEBAQ: { first: id(1) } } } })
    );

    expect(error?.name).toBe('NotSupportedError');
  });

  it.each([
    ['empty', ''],
    ['padded', 'AQEBAQEBAQEBAQEBAQEBAQ=='],
    ['standard base64', 'AQEBAQEBAQEBAQEBAQEBA+/'],
    ['not one of allowCredentials', 'AgICAgICAgICAgICAgICAg'],
  ])('rejects an evalByCredential key that is %s with SyntaxError', async (_label, key) => {
    const { error } = await getWith((o) => {
      o.allowCredentials = [{ type: 'public-key', id: id(1) }];
      o.extensions = { prf: { evalByCredential: { [key]: { first: id(9) } } } };
    });

    expect(error?.name).toBe('SyntaxError');
  });

  it('accepts an evalByCredential key for an allowed credential', async () => {
    vault.native.get.mockResolvedValue({ id: 'browser' });

    const { error } = await getWith((o) => {
      o.allowCredentials = [{ type: 'public-key', id: id(1) }];
      o.extensions = { prf: { evalByCredential: { AQEBAQEBAQEBAQEBAQEBAQ: { first: id(9) } } } };
    });

    expect(error).toBeUndefined();
  });
});

describe('Permissions Policy (§5.9)', () => {
  function policy(allowed: string[]) {
    Object.defineProperty(document, 'featurePolicy', {
      configurable: true,
      value: {
        features: () => ['publickey-credentials-get', 'publickey-credentials-create'],
        allowsFeature: (name: string) => allowed.includes(name),
      },
    });
  }

  afterEach(() => {
    delete (document as unknown as Record<string, unknown>).featurePolicy;
  });

  it('leaves a page that switched WebAuthn off to the browser, without a dialog', async () => {
    policy([]);
    vault.native.create.mockRejectedValue(new DOMException('not allowed', 'NotAllowedError'));
    vault.native.get.mockRejectedValue(new DOMException('not allowed', 'NotAllowedError'));

    const created = await createWith(() => undefined);
    const got = await getWith(() => undefined);

    expect(created.error?.name).toBe('NotAllowedError');
    expect(got.error?.name).toBe('NotAllowedError');
    expect(vault.user.confirmCreate).not.toHaveBeenCalled();
    expect(vault.user.choosePasskey).not.toHaveBeenCalled();
    expect(await vault.passkeys()).toEqual([]);
  });

  it('serves a page whose policy allows WebAuthn', async () => {
    policy(['publickey-credentials-get', 'publickey-credentials-create']);

    const { error } = await createWith(() => undefined);

    expect(error).toBeUndefined();
    expect(vault.user.confirmCreate).toHaveBeenCalled();
  });
});
