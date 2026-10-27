/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Real relying parties' ceremony options, run through the vault on each
 * site's own origin and verified like the site's server would.
 *
 * tests/fixtures/real-world-options.json holds 60 option payloads that real
 * sites and server libraries send (Google, Microsoft, Meta, GitHub, Apple,
 * Amazon, PayPal, Binance, Sony, Bitwarden, SimpleWebAuthn, py_webauthn,
 * webauthn-rs, ...), each with the bug report, capture or source file it
 * came from in `source`. They are what broke other passkey managers: string
 * alg values, RS1 listed first, pre-standard transports, Uint8Array views
 * into one shared buffer, related-origin RP IDs, appid and largeBlob next to
 * PRF. Related Origin Requests are answered with the live
 * /.well-known/webauthn files of login.microsoft.com and accounts.meta.com
 * (tests/fixtures/well-known), fetched when the corpus was made.
 */

import * as fs from 'fs';
import * as path from 'path';
import { setupVault, vaultReady } from '../helpers/harness';
import { outcome } from '../helpers/ceremony';
import { b64url, fromB64url, toBytes } from '../helpers/bytes';
import { oracleAuthentication, oracleRegistration } from '../helpers/oracle';
import {
  creationOptionsFromJSON,
  random,
  registrationJSON,
  requestOptionsFromJSON,
} from '../helpers/options';
import { verifyAuthentication, verifyRegistration } from '../helpers/rp-verifier';

interface Fixture {
  id: string;
  rp: string;
  ceremony: 'create' | 'get';
  origin: string;
  provenance: string;
  source: string;
  options: Record<string, any>;
  mediation?: CredentialMediationRequirement;
  notes: string;
}

const FIXTURES: Fixture[] = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../fixtures/real-world-options.json'), 'utf8')
);
const WELL_KNOWN = path.join(__dirname, '../fixtures/well-known');

/** What the vault should do with a fixture, where it is not "handle it". */
const EXPECTED: Record<string, 'browser' | 'TypeError'> = {
  // The site accepts EdDSA only: the vault cannot make that key.
  'eddsa-only-developer-test-site': 'browser',
  // Strings where BufferSources belong; the browser throws TypeError.
  'string-challenge-developer-report': 'TypeError',
};

const vault = setupVault('https://example.com/');

beforeAll(async () => {
  // Serve each RP's /.well-known/webauthn from the fixtures, as Chrome would fetch it.
  (globalThis as Record<string, unknown>).fetch = jest.fn(async (url: string) => {
    const match = /^https:\/\/([^/]+)\/\.well-known\/webauthn$/.exec(String(url));
    const file = match && path.join(WELL_KNOWN, `${match[1]}.json`);
    if (!file || !fs.existsSync(file)) {
      return {
        ok: false,
        status: 404,
        headers: { get: (name: string) => (name === 'content-type' ? 'text/html' : null) },
        text: async () => 'not found',
      };
    }
    const body = fs.readFileSync(file, 'utf8');
    return {
      ok: true,
      status: 200,
      headers: { get: (name: string) => (name === 'content-type' ? 'application/json' : null) },
      text: async () => body,
    };
  });
  await vaultReady(vault);
});

beforeEach(() => vault.reset());

function rpIdOf(fixture: Fixture): string {
  const explicit = fixture.ceremony === 'create' ? fixture.options.rp?.id : fixture.options.rpId;
  return explicit || new URL(fixture.origin).hostname;
}

/** Turn the JSON options into what the page passes, buffers as the site builds them. */
function pageOptions(fixture: Fixture): any {
  const options: any =
    fixture.ceremony === 'create'
      ? creationOptionsFromJSON(fixture.options)
      : requestOptionsFromJSON(fixture.options);
  if (fixture.id.startsWith('sentry-')) {
    // Sentry decodes its options from CBOR, so every buffer is a view at an
    // offset into one shared ArrayBuffer (bitwarden/clients#8756).
    const shared = new Uint8Array(4096).fill(0xa5);
    let offset = 17;
    const view = (buffer: ArrayBuffer) => {
      const bytes = new Uint8Array(buffer);
      shared.set(bytes, offset);
      const out = shared.subarray(offset, offset + bytes.length);
      offset += bytes.length + 9;
      return out;
    };
    options.challenge = view(options.challenge);
    options.user.id = view(options.user.id);
  }
  return options;
}

const creates = FIXTURES.filter((f) => f.ceremony === 'create');
const gets = FIXTURES.filter((f) => f.ceremony === 'get');

describe.each(creates.map((f) => [f.id, f] as const))('registration: %s', (_id, fixture) => {
  it(`is handled the way the browser would (${fixture.provenance})`, async () => {
    vault.goto(fixture.origin);
    vault.native.create.mockResolvedValue({ id: 'browser-credential' });
    const expected = EXPECTED[fixture.id];

    if (expected === 'TypeError') {
      const { error } = await outcome(
        navigator.credentials.create({ publicKey: fixture.options as any })
      );
      expect(error).toBeInstanceOf(TypeError);
      expect(await vault.passkeys()).toEqual([]);
      return;
    }

    const options = pageOptions(fixture);
    const credential: any = await navigator.credentials.create({ publicKey: options });

    if (expected === 'browser') {
      expect(credential.id).toBe('browser-credential');
      expect(vault.user.confirmCreate).not.toHaveBeenCalled();
      return;
    }

    const rpId = rpIdOf(fixture);
    const requireUserVerification =
      fixture.options.authenticatorSelection?.userVerification === 'required';
    const record = await verifyRegistration(credential, {
      challenge: fromB64url(fixture.options.challenge),
      origin: fixture.origin,
      rpId,
      userId: fromB64url(fixture.options.user.id),
      pubKeyCredParams: fixture.options.pubKeyCredParams,
      requireUserVerification,
      extensions: fixture.options.extensions,
    });
    await oracleRegistration(credential, {
      challenge: fixture.options.challenge,
      origin: fixture.origin,
      rpId,
      requireUserVerification,
    });
    expect(record.id).toBe(credential.id);
    expect(vault.user.confirmCreate).toHaveBeenCalledWith(
      rpId,
      expect.any(String),
      expect.anything()
    );
  });
});

describe.each(gets.map((f) => [f.id, f] as const))('sign-in: %s', (_id, fixture) => {
  it(`signs with a vault passkey for the site (${fixture.provenance})`, async () => {
    vault.goto(fixture.origin);
    const rpId = rpIdOf(fixture);
    const userId = random(32);
    const registrationOptions = registrationJSON({
      rp: { name: fixture.rp, id: rpId },
      user: { id: b64url(userId), name: 'user@example.com', displayName: 'User' },
    });
    const registered: any = await navigator.credentials.create({
      publicKey: creationOptionsFromJSON(registrationOptions),
    });
    const record = await verifyRegistration(registered, {
      challenge: fromB64url(registrationOptions.challenge),
      origin: fixture.origin,
      rpId,
      userId,
      pubKeyCredParams: registrationOptions.pubKeyCredParams,
    });
    const oracle = await oracleRegistration(registered, {
      challenge: registrationOptions.challenge,
      origin: fixture.origin,
      rpId,
    });

    // Keep the site's own credential list, and add the vault passkey to it.
    const json = { ...fixture.options };
    if (json.allowCredentials?.length) {
      json.allowCredentials = [
        ...json.allowCredentials,
        { type: 'public-key', id: record.id, transports: ['internal'] },
      ];
    }
    if (json.extensions?.prf?.evalByCredential) {
      // The spec's test vector keys its entry by its own credential; re-key it to ours.
      const [entry] = Object.values(json.extensions.prf.evalByCredential);
      json.extensions = {
        ...json.extensions,
        prf: { ...json.extensions.prf, evalByCredential: { [record.id]: entry } },
      };
    }
    const assertion: any = await navigator.credentials.get({
      publicKey: requestOptionsFromJSON(json),
      ...(fixture.mediation && { mediation: fixture.mediation }),
    });

    const requireUserVerification = json.userVerification === 'required';
    const result = await verifyAuthentication(assertion, {
      challenge: fromB64url(json.challenge),
      origin: fixture.origin,
      rpId,
      record,
      allowCredentials: (json.allowCredentials || []).map((c: any) => fromB64url(c.id)),
      requireUserVerification,
      extensions: json.extensions,
    });
    await oracleAuthentication(assertion, {
      challenge: json.challenge,
      origin: fixture.origin,
      rpId,
      credential: oracle,
      requireUserVerification,
    });
    expect(result.userHandle).toEqual(userId);
    if (json.extensions?.prf?.eval || json.extensions?.prf?.evalByCredential) {
      expect(toBytes(assertion.getClientExtensionResults().prf.results.first)).toHaveLength(32);
    }
  });
});

describe('the corpus', () => {
  it('covers the shapes that broke other passkey managers', () => {
    const ids = FIXTURES.map((f) => f.id);
    expect(ids).toEqual(
      expect.arrayContaining([
        'sony-playstation-create-string-algs',
        'meta-facebook-create-related-origin',
      ])
    );
    expect(FIXTURES.length).toBeGreaterThanOrEqual(60);
    for (const fixture of FIXTURES) expect(fixture.source).toMatch(/^https?:\/\//);
  });
});
