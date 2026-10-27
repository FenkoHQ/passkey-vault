/**
 * WebAuthn through the built extension in a real Chromium.
 *
 * The jsdom suites run the extension's code; this runs the extension
 * itself, as a user has it: the bundled content script and page shim
 * injected by Chrome, the service worker receiving Chrome's real sender
 * objects, the in-page dialogs clicked with trusted input, on HTTPS sites
 * that include subdomains, parent-domain RP IDs, a cross-site iframe and a
 * Related Origin Request served from a real /.well-known/webauthn.
 *
 * The second half is differential: every edge case also runs against
 * Chrome's own WebAuthn client (a browser without the extension, with a
 * CDP virtual authenticator), and the vault must fail or succeed the same
 * way. That is what found the case-sensitive RP ID and the prf/credProps
 * input rules fixed in this series.
 *
 *   npm run test:e2e:webauthn
 */

import type { BrowserContext, Page } from 'playwright';
import {
  addVirtualAuthenticator,
  launchNative,
  launchWithVault,
  startSite,
  type Site,
} from './browsers';
import { b64url, fromB64url } from '../helpers/bytes';
import { oracleAuthentication, oracleRegistration, type OracleCredential } from '../helpers/oracle';
import { syntheticCredential, type CredentialParts } from '../helpers/synthetic-credential';
import {
  verifyAuthentication,
  verifyRegistration,
  type CredentialRecord,
} from '../helpers/rp-verifier';
import { decodeCbor } from '../helpers/cbor-strict';

// The verifier checks prototypes; in Node, give it classes to check against.
for (const name of [
  'PublicKeyCredential',
  'AuthenticatorAttestationResponse',
  'AuthenticatorAssertionResponse',
]) {
  (globalThis as Record<string, unknown>)[name] ??= class {};
}

const VAULT_AAGUID = 'd2717a32985148a89961b264c97a411a';

let site: Site;
let vault: BrowserContext;
let native: BrowserContext;

beforeAll(async () => {
  site = await startSite();
  ({ context: vault } = await launchWithVault(site));
  native = await launchNative(site);
});

afterAll(async () => {
  await vault?.close();
  await native?.close();
  await site?.close();
});

const random = (length: number) => b64url(crypto.getRandomValues(new Uint8Array(length)));

function creationJSON(rpId: string, overrides: Record<string, unknown> = {}) {
  return {
    challenge: random(32),
    rp: { name: 'Test RP', id: rpId },
    user: { id: random(16), name: 'alice@example.test', displayName: 'Alice' },
    pubKeyCredParams: [
      { type: 'public-key', alg: -8 },
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
    ],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    attestation: 'none',
    ...overrides,
  };
}

interface PageResult {
  ok: boolean;
  name?: string;
  message?: string;
  json?: any;
  /** What the page itself saw: prototypes, tags, accessors. */
  checks?: Record<string, unknown>;
}

/**
 * Click in the vault's dialog: an extension page in a frame the page cannot
 * reach (a closed shadow root), so it is found among the page's frames by
 * its URL rather than by a selector.
 */
async function clickInDialog(page: Page, selector: string, timeout = 8000): Promise<void> {
  const deadline = Date.now() + timeout;
  for (;;) {
    const dialog = page.frames().find((frame) => frame.url().includes('/vault-dialog.html'));
    if (dialog) {
      await dialog.locator(selector).click({ timeout: Math.max(deadline - Date.now(), 1) });
      return;
    }
    if (Date.now() > deadline) throw new Error('No vault dialog');
    await page.waitForTimeout(50);
  }
}

/** Run create() in the page (or a frame), clicking the vault's dialog if one opens. */
async function create(
  page: Page,
  json: unknown,
  options: { frame?: string; click?: boolean } = {}
): Promise<PageResult> {
  const host = options.frame ? page.frame({ url: /frame/ })! : page.mainFrame();
  const result = host.evaluate(async (input: any) => {
    try {
      const credential: any = await navigator.credentials.create({
        publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(input),
      });
      const response = credential.response;
      return {
        ok: true,
        json: credential.toJSON(),
        checks: {
          isPublicKeyCredential: credential instanceof PublicKeyCredential,
          isAttestationResponse: response instanceof AuthenticatorAttestationResponse,
          tag: Object.prototype.toString.call(credential),
          stringifies: JSON.stringify(credential).length > 0,
          transports: response.getTransports(),
          algorithm: response.getPublicKeyAlgorithm(),
          extensions: credential.getClientExtensionResults(),
        },
      };
    } catch (error: any) {
      return { ok: false, name: error?.name, message: error?.message };
    }
  }, json);
  if (options.click !== false) {
    await Promise.race([clickInDialog(page, '#pkv-create').catch(() => undefined), result]);
  }
  return result;
}

/** Whether a vault dialog is on the page, in any of its frames. */
const dialogOpen = (page: Page) =>
  page.frames().some((frame) => frame.url().includes('/vault-dialog.html'));

async function get(
  page: Page,
  json: unknown,
  options: { click?: boolean } = {}
): Promise<PageResult> {
  const result = page.evaluate(async (input: any) => {
    try {
      const credential: any = await navigator.credentials.get({
        publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(input),
      });
      return {
        ok: true,
        json: credential.toJSON(),
        checks: {
          isPublicKeyCredential: credential instanceof PublicKeyCredential,
          isAssertionResponse: credential.response instanceof AuthenticatorAssertionResponse,
          extensions: credential.getClientExtensionResults(),
          prfFirstLength: credential.getClientExtensionResults().prf?.results?.first?.byteLength,
        },
      };
    } catch (error: any) {
      return { ok: false, name: error?.name, message: error?.message };
    }
  }, json);
  if (options.click !== false) {
    await Promise.race([clickInDialog(page, '#pkv-continue').catch(() => undefined), result]);
  }
  return result;
}

/** Client extension results from their JSON form, PRF results back as ArrayBuffers. */
function extensionResultsFromJSON(json: any): Record<string, unknown> {
  const results = { ...(json ?? {}) };
  if (results.prf?.results) {
    const buffer = (text: string) => fromB64url(text).slice().buffer;
    results.prf = {
      ...results.prf,
      results: Object.fromEntries(
        Object.entries(results.prf.results).map(([name, value]) => [name, buffer(value as string)])
      ),
    };
  }
  return results;
}

function partsFromJSON(json: any): CredentialParts {
  const response = json.response;
  const common = {
    id: json.id,
    rawId: fromB64url(json.rawId),
    authenticatorAttachment: json.authenticatorAttachment,
    clientDataJSON: fromB64url(response.clientDataJSON),
    extensionResults: extensionResultsFromJSON(json.clientExtensionResults),
    extensionResultsJSON: json.clientExtensionResults,
  };
  return response.attestationObject
    ? {
        ...common,
        attestationObject: fromB64url(response.attestationObject),
        authenticatorData: fromB64url(response.authenticatorData),
        publicKey: response.publicKey ? fromB64url(response.publicKey) : null,
        publicKeyAlgorithm: response.publicKeyAlgorithm,
        transports: response.transports,
      }
    : {
        ...common,
        authenticatorData: fromB64url(response.authenticatorData),
        signature: fromB64url(response.signature),
        userHandle: response.userHandle ? fromB64url(response.userHandle) : null,
      };
}

function aaguidOf(json: any): string {
  const authData = fromB64url(json.response.authenticatorData);
  return Buffer.from(authData.slice(37, 53)).toString('hex');
}

async function verifyCreated(
  result: PageResult,
  json: any,
  origin: string,
  rpId: string,
  extra: { topOrigin?: string } = {}
): Promise<{ record: CredentialRecord; oracle: OracleCredential }> {
  expect(result).toMatchObject({ ok: true });
  expect(result.checks).toMatchObject({
    isPublicKeyCredential: true,
    isAttestationResponse: true,
    tag: '[object PublicKeyCredential]',
    stringifies: true,
    algorithm: -7,
  });
  const record = await verifyRegistration(syntheticCredential(partsFromJSON(result.json)), {
    challenge: fromB64url(json.challenge),
    origin,
    rpId,
    userId: fromB64url(json.user.id),
    pubKeyCredParams: json.pubKeyCredParams,
    extensions: json.extensions,
    topOrigin: extra.topOrigin,
  });
  const oracle = await oracleRegistration(result.json, { challenge: json.challenge, origin, rpId });
  return { record, oracle };
}

describe('ceremonies through the installed extension', () => {
  let page: Page;

  beforeAll(async () => {
    page = await vault.newPage();
  });

  afterAll(() => page.close());

  let registered: { record: CredentialRecord; oracle: OracleCredential };

  it('registers a passkey a strict RP and SimpleWebAuthn accept', async () => {
    await page.goto('https://shop.test/account');
    const json = creationJSON('shop.test');

    const result = await create(page, json);

    registered = await verifyCreated(result, json, 'https://shop.test', 'shop.test');
    expect(aaguidOf(result.json)).toBe(VAULT_AAGUID);
    expect(result.checks!.extensions).toEqual({});
  });

  it('signs in with it, the counter moving forward each time', async () => {
    for (let i = 1; i <= 3; i++) {
      const json = { challenge: random(32), rpId: 'shop.test', userVerification: 'preferred' };
      const result = await get(page, json);

      expect(result).toMatchObject({
        ok: true,
        checks: { isPublicKeyCredential: true, isAssertionResponse: true },
      });
      const verified = await verifyAuthentication(syntheticCredential(partsFromJSON(result.json)), {
        challenge: fromB64url(json.challenge),
        origin: 'https://shop.test',
        rpId: 'shop.test',
        record: registered.record,
      });
      registered.record.signCount = verified.signCount;
      registered.oracle.counter = await oracleAuthentication(result.json, {
        challenge: json.challenge,
        origin: 'https://shop.test',
        rpId: 'shop.test',
        credential: registered.oracle,
      });
      expect(verified.signCount).toBe(i);
    }
  });

  it('uses a parent-domain RP ID from one subdomain and signs from another', async () => {
    await page.goto('https://www.bank.test/');
    const json = creationJSON('bank.test');
    const created = await verifyCreated(
      await create(page, json),
      json,
      'https://www.bank.test',
      'bank.test'
    );

    await page.goto('https://login.bank.test/');
    const request = { challenge: random(32), rpId: 'bank.test' };
    const result = await get(page, request);

    await verifyAuthentication(syntheticCredential(partsFromJSON(result.json)), {
      challenge: fromB64url(request.challenge),
      origin: 'https://login.bank.test',
      rpId: 'bank.test',
      record: created.record,
    });
  });

  it('reports prf.enabled at registration and evaluates PRF at sign-in', async () => {
    await page.goto('https://notes.test/');
    const json = creationJSON('notes.test', { extensions: { prf: {} } });
    const created = await create(page, json);
    expect(created.checks!.extensions).toEqual({ prf: { enabled: true } });
    const { record } = await verifyCreated(created, json, 'https://notes.test', 'notes.test');

    const salt = b64url(new TextEncoder().encode('per-user salt'));
    const outputs: string[] = [];
    for (let i = 0; i < 2; i++) {
      const request = {
        challenge: random(32),
        rpId: 'notes.test',
        extensions: { prf: { eval: { first: salt } } },
      };
      const result = await get(page, request);
      expect(result.checks!.prfFirstLength).toBe(32);
      outputs.push(result.json.clientExtensionResults.prf.results.first);
      await verifyAuthentication(syntheticCredential(partsFromJSON(result.json)), {
        challenge: fromB64url(request.challenge),
        origin: 'https://notes.test',
        rpId: 'notes.test',
        record,
        strictCounter: false,
      });
    }
    expect(outputs[0]).toBe(outputs[1]);
  });

  it('marks a ceremony in a cross-site iframe as crossOrigin, naming the top origin', async () => {
    await page.goto('https://checkout.shop.test/');
    await page.evaluate(() => {
      const frame = document.createElement('iframe');
      frame.src = 'https://pay.test/frame';
      frame.allow = 'publickey-credentials-create; publickey-credentials-get';
      frame.width = '800';
      frame.height = '600';
      document.getElementById('frames')!.appendChild(frame);
      return new Promise((resolve) => (frame.onload = resolve));
    });
    // A user gesture inside the frame, which create() in a cross-origin frame needs.
    await page.frameLocator('iframe').locator('h1').click();
    const json = creationJSON('pay.test');

    const result = await create(page, json, { frame: 'iframe' });

    await verifyCreated(result, json, 'https://pay.test', 'pay.test', {
      topOrigin: 'https://checkout.shop.test',
    });
    const clientData = JSON.parse(
      Buffer.from(fromB64url(result.json.response.clientDataJSON)).toString()
    );
    expect(clientData).toMatchObject({
      crossOrigin: true,
      topOrigin: 'https://checkout.shop.test',
    });
  });

  it('honours a Related Origin Request from the RP’s /.well-known/webauthn', async () => {
    site.routes.set('/.well-known/webauthn', (host) =>
      host === 'accounts.brand.test'
        ? [200, 'application/json', JSON.stringify({ origins: ['https://www.brand-shop.test'] })]
        : [404, 'text/plain', 'not found']
    );
    await page.goto('https://www.brand-shop.test/');
    const json = creationJSON('accounts.brand.test');

    const result = await create(page, json);

    await verifyCreated(result, json, 'https://www.brand-shop.test', 'accounts.brand.test');
    expect(aaguidOf(result.json)).toBe(VAULT_AAGUID);
  });

  it('is in place before the page\u2019s first script runs', async () => {
    site.routes.set('/early', () => [
      200,
      'text/html; charset=utf-8',
      `<!doctype html><html><head><script>
        window.earliest = {
          get: String(navigator.credentials.get).includes('[native code]') ? 'native' : 'vault',
          create: String(navigator.credentials.create).includes('[native code]') ? 'native' : 'vault',
        };
      </script></head><body><h1>early</h1></body></html>`,
    ]);

    await page.goto('https://early.test/early');

    expect(await page.evaluate(() => (window as any).earliest)).toEqual({
      get: 'vault',
      create: 'vault',
    });
  });

  it('answers a request made the moment the page loads', async () => {
    await page.goto('https://instant.test/');
    const json = creationJSON('instant.test');

    await verifyCreated(await create(page, json), json, 'https://instant.test', 'instant.test');
  });

  it('stores nothing when the page aborts while the dialog is open', async () => {
    await page.goto('https://abort.test/');
    const before = await page
      .context()
      .serviceWorkers()[0]
      .evaluate(async () => {
        const { passkeys = [] } = await chrome.storage.local.get('passkeys');
        return passkeys.length;
      });

    const outcome = await page.evaluate(async (input: any) => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 500);
      try {
        await navigator.credentials.create({
          publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(input),
          signal: controller.signal,
        });
        return 'created';
      } catch (error: any) {
        return error.name;
      }
    }, creationJSON('abort.test'));

    expect(outcome).toBe('AbortError');
    await page.waitForTimeout(500);
    expect(dialogOpen(page)).toBe(false);
    const after = await page
      .context()
      .serviceWorkers()[0]
      .evaluate(async () => {
        const { passkeys = [] } = await chrome.storage.local.get('passkeys');
        return passkeys.length;
      });
    expect(after).toBe(before);
  });
});

/**
 * Each case runs in both browsers. Vault-browser pages also get a virtual
 * authenticator, so a request the vault hands to the browser is answered
 * the way it would be without the vault, rather than waiting for a
 * security key.
 */
type Case = [string, 'create' | 'get', (options: any) => void];

const CASES: Case[] = [
  ['baseline registration', 'create', () => undefined],
  ['user.id of 65 bytes', 'create', (o) => (o.user.id = random(65))],
  ['empty user.id', 'create', (o) => (o.user.id = '')],
  ['no user.displayName', 'create', (o) => delete o.user.displayName],
  ['no rp.name', 'create', (o) => delete o.rp.name],
  ['empty pubKeyCredParams', 'create', (o) => (o.pubKeyCredParams = [])],
  [
    'only an unknown credential type',
    'create',
    (o) => (o.pubKeyCredParams = [{ type: 'secret-key', alg: -7 }]),
  ],
  ['alg as a string', 'create', (o) => (o.pubKeyCredParams = [{ type: 'public-key', alg: '-7' }])],
  ['RP ID in upper case', 'create', (o) => (o.rp.id = 'SHOP.TEST')],
  ['empty RP ID', 'create', (o) => (o.rp.id = '')],
  ['RP ID with a trailing dot', 'create', (o) => (o.rp.id = 'shop.test.')],
  ['RP ID that is a public suffix', 'create', (o) => (o.rp.id = 'test')],
  ['RP ID with a port', 'create', (o) => (o.rp.id = 'shop.test:443')],
  ['RP ID of a sibling', 'create', (o) => (o.rp.id = 'other.test')],
  ['prf {} at registration', 'create', (o) => (o.extensions = { prf: {} })],
  [
    'prf evalByCredential at registration',
    'create',
    (o) =>
      (o.extensions = { prf: { evalByCredential: { AAAAAAAAAAAAAAAAAAAAAA: { first: 'AAAA' } } } }),
  ],
  ['credProps at registration', 'create', (o) => (o.extensions = { credProps: true })],
  ['baseline sign-in', 'get', () => undefined],
  ['credProps at sign-in', 'get', (o) => (o.extensions = { credProps: true })],
  [
    'prf evalByCredential without allowCredentials',
    'get',
    (o) =>
      (o.extensions = { prf: { evalByCredential: { AAAAAAAAAAAAAAAAAAAAAA: { first: 'AAAA' } } } }),
  ],
  [
    'prf evalByCredential with a padded key',
    'get',
    (o) => {
      o.allowCredentials = [{ type: 'public-key', id: 'AQIDBAUGBwgJCgsMDQ4PEA' }];
      o.extensions = {
        prf: { evalByCredential: { 'AQIDBAUGBwgJCgsMDQ4PEA==': { first: 'AAAA' } } },
      };
    },
  ],
  [
    'prf evalByCredential naming a credential not allowed',
    'get',
    (o) => {
      o.allowCredentials = [{ type: 'public-key', id: 'AQIDBAUGBwgJCgsMDQ4PEA' }];
      o.extensions = { prf: { evalByCredential: { AAAAAAAAAAAAAAAAAAAAAA: { first: 'AAAA' } } } };
    },
  ],
  ['RP ID in upper case at sign-in', 'get', (o) => (o.rpId = 'SHOP.TEST')],
  ['empty RP ID at sign-in', 'get', (o) => (o.rpId = '')],
  ['public suffix RP ID at sign-in', 'get', (o) => (o.rpId = 'test')],
];

describe('the vault fails and succeeds exactly where Chrome does', () => {
  let vaultPage: Page;
  let nativePage: Page;

  beforeAll(async () => {
    vaultPage = await vault.newPage();
    nativePage = await native.newPage();
    for (const page of [vaultPage, nativePage]) {
      await page.goto('https://shop.test/');
      await addVirtualAuthenticator(page);
    }
    // Something to sign in with on both sides: a vault passkey, and a
    // credential on Chrome's virtual authenticator.
    expect((await create(vaultPage, creationJSON('shop.test'))).ok).toBe(true);
    expect(
      (
        await create(
          nativePage,
          creationJSON('shop.test', { authenticatorSelection: { residentKey: 'required' } }),
          { click: false }
        )
      ).ok
    ).toBe(true);
  });

  afterAll(async () => {
    await vaultPage.close();
    await nativePage.close();
  });

  it.each(CASES)('%s', async (_label, ceremony, mutate) => {
    const json: any =
      ceremony === 'create'
        ? creationJSON('shop.test')
        : { challenge: random(32), rpId: 'shop.test', timeout: 20000 };
    mutate(json);

    const run = (page: Page, click: boolean) =>
      ceremony === 'create' ? create(page, json, { click }) : get(page, json, { click });
    const [chrome, withVault] = [await run(nativePage, false), await run(vaultPage, true)];
    const outcome = (result: PageResult) =>
      result.ok ? 'resolves' : `rejects with ${result.name}`;

    expect(outcome(withVault)).toBe(outcome(chrome));
  });
});

/**
 * Cross-origin iframes may only use WebAuthn when the embedding page
 * delegates it (Permissions Policy publickey-credentials-get/-create), and
 * create() there also needs a user gesture in the frame. The vault must
 * not open its dialog where Chrome would refuse.
 */
describe('cross-origin iframes follow the embedder’s permissions, as in Chrome', () => {
  async function framed(page: Page, allow: string): Promise<Page> {
    await page.goto('https://portal.test/');
    await page.evaluate((allowAttribute) => {
      document.getElementById('frames')!.innerHTML = '';
      const frame = document.createElement('iframe');
      frame.src = 'https://widget.test/frame';
      if (allowAttribute) frame.allow = allowAttribute;
      document.getElementById('frames')!.appendChild(frame);
      return new Promise((resolve) => (frame.onload = resolve));
    }, allow);
    return page;
  }

  async function inFrame(
    page: Page,
    ceremony: 'create' | 'get',
    gesture: boolean
  ): Promise<string> {
    const frame = page.frame({ url: /widget\.test/ })!;
    await addVirtualAuthenticator(page);
    if (gesture) await page.frameLocator('iframe').locator('h1').click();
    const json =
      ceremony === 'create'
        ? creationJSON('widget.test')
        : { challenge: random(32), rpId: 'widget.test', timeout: 5000 };
    const result = frame.evaluate(
      async ([kind, input]: [string, any]) => {
        try {
          if (kind === 'create') {
            await navigator.credentials.create({
              publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(input),
            });
          } else {
            await navigator.credentials.get({
              publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(input),
            });
          }
          return 'resolves';
        } catch (error: any) {
          return `rejects with ${error.name}`;
        }
      },
      [ceremony, json] as [string, any]
    );
    const dialog = clickInDialog(
      page,
      ceremony === 'create' ? '#pkv-create' : '#pkv-continue',
      4000
    )
      .then(() => 'vault dialog')
      .catch(() => 'no dialog');
    const [outcome, ui] = await Promise.all([result, dialog]);
    return `${outcome} (${ui})`;
  }

  const CASES: Array<[string, string, 'create' | 'get', boolean]> = [
    ['create without delegation', '', 'create', true],
    ['create with delegation and a gesture', 'publickey-credentials-create', 'create', true],
    ['create with delegation but no gesture', 'publickey-credentials-create', 'create', false],
    ['get without delegation', '', 'get', false],
  ];

  it.each(CASES)('%s', async (_label, allow, ceremony, gesture) => {
    const chromePage = await framed(await native.newPage(), allow);
    const vaultPage = await framed(await vault.newPage(), allow);
    try {
      const chrome = (await inFrame(chromePage, ceremony, gesture)).replace(/ \(.*\)$/, '');
      const withVault = await inFrame(vaultPage, ceremony, gesture);

      // Where Chrome refuses, the vault refuses too and never shows its dialog.
      if (chrome !== 'resolves') expect(withVault).toBe(`${chrome} (no dialog)`);
      else expect(withVault.startsWith('resolves')).toBe(true);
    } finally {
      await chromePage.close();
      await vaultPage.close();
    }
  });
});
