/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Authentication ceremonies (navigator.credentials.get) through the real
 * shim, content script and background, verified per WebAuthn Level 3 §7.2
 * and by SimpleWebAuthn.
 */

import { setupVault, vaultReady, type PasskeyOption } from '../helpers/harness';
import { authenticate, outcome, register } from '../helpers/ceremony';
import { b64url, hex, sha256, toBytes } from '../helpers/bytes';
import { FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV, parseAuthenticatorData } from '../helpers/rp-verifier';
import { authenticationJSON, random, requestOptionsFromJSON } from '../helpers/options';

const vault = setupVault('https://example.com/login');

beforeAll(() => vaultReady(vault));
beforeEach(async () => {
  await vault.reset();
  vault.goto('https://example.com/login');
});

function flagsOf(assertion: any): number {
  return toBytes(assertion.response.authenticatorData)[32];
}

describe('signing in with a vault passkey', () => {
  it('passes §7.2 and SimpleWebAuthn for a discoverable (usernameless) sign-in', async () => {
    const registration = await register();
    const { result } = await authenticate(registration);

    expect(result.userHandle).toEqual(registration.record.userHandle);
  });

  it('serialises clientDataJSON exactly as §5.8.1.1', async () => {
    const registration = await register();
    const { assertion, json } = await authenticate(registration);

    expect(new TextDecoder().decode(assertion.response.clientDataJSON)).toBe(
      `{"type":"webauthn.get","challenge":"${json.challenge}","origin":"https://example.com","crossOrigin":false}`
    );
  });

  it('signs with the credential the server names in allowCredentials', async () => {
    const registration = await register();
    const other = b64url(random(32));
    const { assertion } = await authenticate(registration, {
      allowCredentials: [
        { type: 'public-key', id: other, transports: ['usb', 'nfc'] },
        { type: 'public-key', id: registration.record.id, transports: ['internal', 'hybrid'] },
      ],
    });

    expect(assertion.id).toBe(registration.record.id);
  });

  it('offers only allowCredentials passkeys when several accounts exist', async () => {
    const alice = await register({
      user: { id: b64url(random(16)), name: 'alice', displayName: 'Alice' },
    });
    await register({ user: { id: b64url(random(16)), name: 'bob', displayName: 'Bob' } });

    await authenticate(alice, { allowCredentials: [{ type: 'public-key', id: alice.record.id }] });

    const offered: PasskeyOption[] = vault.user.choosePasskey.mock.calls[0][0];
    expect(offered.map((o) => o.userName)).toEqual(['alice']);
  });

  it('signs with whichever account the user picks', async () => {
    await register({ user: { id: b64url(random(16)), name: 'alice', displayName: 'Alice' } });
    const bob = await register({
      user: { id: b64url(random(16)), name: 'bob', displayName: 'Bob' },
    });
    vault.user.choosePasskey.mockImplementation((options: PasskeyOption[]) => ({
      action: 'use',
      id: options.find((o) => o.userName === 'bob')!.id,
    }));

    const { assertion, result } = await authenticate(bob);

    expect(assertion.id).toBe(bob.record.id);
    expect(result.userHandle).toEqual(bob.record.userHandle);
  });

  it('works for a passkey registered to a parent domain, from a subdomain', async () => {
    vault.goto('https://www.example.com/');
    const registration = await register({ rp: { name: 'Example', id: 'example.com' } });
    vault.goto('https://login.example.com/');

    const { assertion } = await authenticate(registration, { rpId: 'example.com' });

    expect(hex(toBytes(assertion.response.authenticatorData).slice(0, 32))).toBe(
      hex(await sha256('example.com'))
    );
  });

  it('sets UP and UV, never AT, and keeps BE/BS from registration', async () => {
    const registration = await register();
    const { assertion } = await authenticate(registration);
    const issues: string[] = [];
    const parsed = parseAuthenticatorData(toBytes(assertion.response.authenticatorData), issues);

    expect(issues).toEqual([]);
    expect(parsed!.flags & (FLAG_UP | FLAG_UV)).toBe(FLAG_UP | FLAG_UV);
    expect(Boolean(parsed!.flags & FLAG_BE)).toBe(registration.record.backupEligible);
    expect(Boolean(parsed!.flags & FLAG_BS)).toBe(registration.record.backupState);
    expect(toBytes(assertion.response.authenticatorData)).toHaveLength(37);
  });

  it('advances the signature counter by one per assertion', async () => {
    const registration = await register();
    const counters: number[] = [];
    for (let i = 0; i < 5; i++) {
      counters.push((await authenticate(registration)).result.signCount);
    }

    expect(counters).toEqual([1, 2, 3, 4, 5]);
    const [stored] = await vault.passkeys();
    expect(stored.counter).toBe(5);
  });

  it('always reports zero when the counter setting is "zero"', async () => {
    await vault.send({ type: 'SET_WEBAUTHN_FLAGS', payload: { flags: { signCounter: 'zero' } } });
    const registration = await register();

    const first = await authenticate(registration, {}, { strictCounter: false });
    const second = await authenticate(registration, {}, { strictCounter: false });

    expect([first.result.signCount, second.result.signCount]).toEqual([0, 0]);
  });

  it('keeps UV clear when verification reporting is off', async () => {
    await vault.send({
      type: 'SET_WEBAUTHN_FLAGS',
      payload: { flags: { userVerification: 'never' } },
    });
    const registration = await register();
    const { assertion } = await authenticate(registration);

    expect(flagsOf(assertion) & FLAG_UV).toBe(0);
  });

  it('produces signatures that verify across many assertions (DER edge cases included)', async () => {
    const registration = await register();
    for (let i = 0; i < 40; i++) await authenticate(registration);
  });

  it('serialises as AuthenticationResponseJSON for the server', async () => {
    const registration = await register();
    const { assertion } = await authenticate(registration);
    const json = JSON.parse(JSON.stringify(assertion));

    expect(Object.keys(json.response).sort()).toEqual(
      ['authenticatorData', 'clientDataJSON', 'signature', 'userHandle'].sort()
    );
    expect(json.rawId).toBe(registration.record.id);
  });
});

describe('when the vault cannot or should not answer', () => {
  it('hands the request to the browser when no vault passkey matches allowCredentials', async () => {
    const registration = await register();
    const nativeCredential = { id: 'native' };
    vault.native.get.mockResolvedValue(nativeCredential);
    const options = requestOptionsFromJSON(
      authenticationJSON({
        rpId: 'example.com',
        allowCredentials: [{ type: 'public-key', id: b64url(random(32)) }],
      })
    );

    const result = await navigator.credentials.get({ publicKey: options });

    expect(result).toBe(nativeCredential);
    expect(vault.native.get).toHaveBeenCalledWith(expect.objectContaining({ publicKey: options }));
    expect(vault.user.choosePasskey).not.toHaveBeenCalled();
    void registration;
  });

  it('hands the request to the browser when the vault has no passkey for the site', async () => {
    vault.native.get.mockResolvedValue({ id: 'native' });

    const result: any = await navigator.credentials.get({
      publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
    });

    expect(result.id).toBe('native');
  });

  it('refuses without asking the browser when the user cancels the picker', async () => {
    await register();
    vault.user.choosePasskey.mockReturnValue({ action: 'cancel' });

    const { error } = await outcome(
      navigator.credentials.get({
        publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
      })
    );

    expect(error?.name).toBe('NotAllowedError');
    expect(vault.native.get).not.toHaveBeenCalled();
  });

  it('opens the browser prompt when the user picks "use another passkey"', async () => {
    await register();
    vault.user.choosePasskey.mockReturnValue({ action: 'passthrough' });
    vault.native.get.mockResolvedValue({ id: 'security-key' });

    const result: any = await navigator.credentials.get({
      publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
    });

    expect(result.id).toBe('security-key');
  });

  it('never offers a passkey from another site', async () => {
    vault.goto('https://other.example.net/');
    await register({ rp: { name: 'Other', id: 'other.example.net' } });
    vault.goto('https://example.com/login');
    vault.native.get.mockResolvedValue({ id: 'native' });

    await navigator.credentials.get({
      publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
    });

    expect(vault.user.choosePasskey).not.toHaveBeenCalled();
  });
});
