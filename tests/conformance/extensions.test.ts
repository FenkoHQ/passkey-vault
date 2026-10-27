/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Client extensions (WebAuthn Level 3 §9, §10). The vault implements prf and
 * credProps; every other extension must be ignored without failing the
 * ceremony or leaking into authenticator data.
 */

import { setupVault, vaultReady } from '../helpers/harness';
import { authenticate, register } from '../helpers/ceremony';
import { b64url, fromB64url, isArrayBuffer, toBytes } from '../helpers/bytes';
import { FLAG_ED } from '../helpers/rp-verifier';
import { random } from '../helpers/options';

const vault = setupVault('https://example.com/login');

beforeAll(() => vaultReady(vault));
beforeEach(async () => {
  await vault.reset();
  vault.goto('https://example.com/login');
});

const SALT_A = b64url(new TextEncoder().encode('fenko prf salt A'));
const SALT_B = b64url(new TextEncoder().encode('fenko prf salt B'));

function prfFirst(credential: any): Uint8Array {
  return toBytes(credential.getClientExtensionResults().prf.results.first);
}

describe('credProps (§10.1.3)', () => {
  it('reports a discoverable credential when requested', async () => {
    const { credential } = await register({ extensions: { credProps: true } });

    expect(credential.getClientExtensionResults().credProps).toEqual({ rk: true });
  });

  it('is absent when not requested', async () => {
    const { credential } = await register({ extensions: {} });

    expect(credential.getClientExtensionResults()).not.toHaveProperty('credProps');
  });

  it('is never part of an authentication result', async () => {
    const registration = await register({ extensions: { credProps: true } });
    const { assertion } = await authenticate(registration);

    expect(assertion.getClientExtensionResults()).not.toHaveProperty('credProps');
  });
});

describe('prf at registration (§10.1.4)', () => {
  it('reports enabled: true when the RP only asks whether PRF is available', async () => {
    const { credential } = await register({ extensions: { prf: {} } });

    expect(credential.getClientExtensionResults().prf).toEqual({ enabled: true });
  });

  it('reports enabled and evaluates eval.first at creation', async () => {
    const { credential } = await register({ extensions: { prf: { eval: { first: SALT_A } } } });
    const prf = credential.getClientExtensionResults().prf;

    expect(prf.enabled).toBe(true);
    expect(isArrayBuffer(prf.results.first)).toBe(true);
    expect(prf.results.first.byteLength).toBe(32);
    expect(prf.results.second).toBeUndefined();
  });

  it('evaluates first and second, which differ for different salts', async () => {
    const { credential } = await register({
      extensions: { prf: { eval: { first: SALT_A, second: SALT_B } } },
    });
    const { first, second } = credential.getClientExtensionResults().prf.results;

    expect(toBytes(first)).not.toEqual(toBytes(second));
  });

  it('carries PRF results in toJSON as base64url', async () => {
    const { credential } = await register({ extensions: { prf: { eval: { first: SALT_A } } } });
    const json = JSON.parse(JSON.stringify(credential));

    expect(json.clientExtensionResults.prf.enabled).toBe(true);
    expect(fromB64url(json.clientExtensionResults.prf.results.first)).toEqual(prfFirst(credential));
  });

  it('keeps the PRF output out of the signed authenticator data', async () => {
    const { credential } = await register({ extensions: { prf: { eval: { first: SALT_A } } } });

    expect(toBytes(credential.response.getAuthenticatorData())[32] & FLAG_ED).toBe(0);
  });

  it('is absent when not requested', async () => {
    const { credential } = await register({ extensions: { credProps: true } });

    expect(credential.getClientExtensionResults()).not.toHaveProperty('prf');
  });
});

describe('prf at authentication (§10.1.4)', () => {
  it('returns the same output as at registration for the same salt', async () => {
    const registration = await register({ extensions: { prf: { eval: { first: SALT_A } } } });
    const { assertion } = await authenticate(registration, {
      extensions: { prf: { eval: { first: SALT_A } } },
    });

    expect(prfFirst(assertion)).toEqual(prfFirst(registration.credential));
    expect(assertion.getClientExtensionResults().prf).not.toHaveProperty('enabled');
  });

  it('is stable across sign-ins and distinct per credential', async () => {
    const one = await register({ extensions: { prf: {} } });
    const two = await register({ extensions: { prf: {} } });
    vault.user.choosePasskey.mockImplementation((options: any[]) => ({
      action: 'use',
      id: options.find((o) => o.credentialId === one.record.id).id,
    }));
    const a = await authenticate(one, { extensions: { prf: { eval: { first: SALT_A } } } });
    const b = await authenticate(one, { extensions: { prf: { eval: { first: SALT_A } } } });
    vault.user.choosePasskey.mockImplementation((options: any[]) => ({
      action: 'use',
      id: options.find((o) => o.credentialId === two.record.id).id,
    }));
    const c = await authenticate(two, { extensions: { prf: { eval: { first: SALT_A } } } });

    expect(prfFirst(a.assertion)).toEqual(prfFirst(b.assertion));
    expect(prfFirst(a.assertion)).not.toEqual(prfFirst(c.assertion));
  });

  it('prefers the evalByCredential entry for the credential used', async () => {
    const registration = await register();
    const viaEval = await authenticate(registration, {
      extensions: { prf: { eval: { first: SALT_B } } },
    });
    const byCredential = await authenticate(registration, {
      allowCredentials: [{ type: 'public-key', id: registration.record.id }],
      extensions: {
        prf: {
          eval: { first: SALT_A },
          evalByCredential: { [registration.record.id]: { first: SALT_B } },
        },
      },
    });

    expect(prfFirst(byCredential.assertion)).toEqual(prfFirst(viaEval.assertion));
  });

  it('returns an empty prf output when no input applies to the credential', async () => {
    const registration = await register();
    const other = b64url(random(32));
    const { assertion } = await authenticate(registration, {
      allowCredentials: [
        { type: 'public-key', id: registration.record.id },
        { type: 'public-key', id: other },
      ],
      extensions: { prf: { evalByCredential: { [other]: { first: SALT_A } } } },
    });

    expect(assertion.getClientExtensionResults().prf).toEqual({});
  });

  it('carries PRF results in toJSON as base64url', async () => {
    const registration = await register();
    const { assertion } = await authenticate(registration, {
      extensions: { prf: { eval: { first: SALT_A } } },
    });
    const json = JSON.parse(JSON.stringify(assertion));

    expect(fromB64url(json.clientExtensionResults.prf.results.first)).toEqual(prfFirst(assertion));
  });

  it('pins the PRF construction: HMAC-SHA-256 over the raw salt with the credential PRF key', async () => {
    // Changing this construction silently changes every PRF output a site has
    // derived keys from, locking users out of data encrypted under them.
    const registration = await register();
    const { assertion } = await authenticate(registration, {
      extensions: { prf: { eval: { first: SALT_A } } },
    });
    const [stored] = await vault.passkeys();
    const key = await crypto.subtle.importKey(
      'raw',
      fromB64url(stored.prfKey) as unknown as BufferSource,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const expected = new Uint8Array(
      await crypto.subtle.sign('HMAC', key, fromB64url(SALT_A) as unknown as BufferSource)
    );

    expect(prfFirst(assertion)).toEqual(expected);
  });
});

describe('extensions the vault does not implement', () => {
  const ignored = {
    appidExclude: 'https://example.com/u2f-app-id.json',
    largeBlob: { support: 'preferred' },
    credBlob: b64url(random(16)),
    credentialProtectionPolicy: 'userVerificationOptional',
    enforceCredentialProtectionPolicy: false,
    hmacCreateSecret: true,
    minPinLength: true,
    uvm: true,
    payment: { isPayment: false },
    someFutureExtension: { anything: [1, 2, 3] },
  };

  it('ignores them at registration without failing or setting ED', async () => {
    const { credential } = await register({ extensions: ignored });
    const results = credential.getClientExtensionResults();

    expect(toBytes(credential.response.getAuthenticatorData())[32] & FLAG_ED).toBe(0);
    for (const name of Object.keys(ignored)) expect(results).not.toHaveProperty(name);
  });

  it('ignores them at authentication', async () => {
    const registration = await register();
    const { assertion } = await authenticate(registration, {
      extensions: {
        appid: 'https://example.com/u2f-app-id.json',
        largeBlob: { read: true },
        getCredBlob: true,
        uvm: true,
      },
    });

    expect(assertion.getClientExtensionResults()).not.toHaveProperty('largeBlob');
  });
});
