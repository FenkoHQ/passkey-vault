/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Chaos: a page uses Related Origin Requests to make the extension fetch.
 *
 * The RP ID in a ceremony is the page's to choose, and when it is not
 * same-site the background fetches https://<rpId>/.well-known/webauthn with
 * the extension's host permissions. Steady state: only public Internet
 * names are fetched, a site the user excluded or a locked vault causes no
 * fetch, and a page cannot make more than a few.
 */

import { setupVault, vaultReady } from '../helpers/harness';
import { outcome } from '../helpers/ceremony';
import {
  authenticationJSON,
  creationOptionsFromJSON,
  registrationJSON,
  requestOptionsFromJSON,
} from '../helpers/options';

const vault = setupVault('https://accountscenter.facebook.com/');
const PAGE = 'https://accountscenter.facebook.com';
const META = 'accounts.meta.com';
const fetched: string[] = [];

beforeAll(async () => {
  (globalThis as Record<string, unknown>).fetch = jest.fn(async (url: string) => {
    fetched.push(String(url));
    const body = JSON.stringify({ origins: [PAGE] });
    return {
      ok: true,
      status: 200,
      headers: { get: (name: string) => (name === 'content-type' ? 'application/json' : null) },
      text: async () => body,
    };
  });
  await vaultReady(vault);
});

beforeEach(async () => {
  await vault.reset();
  vault.goto(`${PAGE}/`);
  fetched.length = 0;
  vault.native.create.mockRejectedValue(new DOMException('browser', 'SecurityError'));
  vault.native.get.mockRejectedValue(new DOMException('browser', 'SecurityError'));
});

function create(rpId: string) {
  const options = creationOptionsFromJSON(registrationJSON({ rp: { name: 'RP', id: rpId } }));
  return outcome(navigator.credentials.create({ publicKey: options }));
}

function get(rpId: string) {
  return outcome(
    navigator.credentials.get({ publicKey: requestOptionsFromJSON(authenticationJSON({ rpId })) })
  );
}

describe('Related Origin Requests from a web page', () => {
  it('are honoured for a public RP ID that lists the page', async () => {
    const { error } = await create(META);

    expect(error).toBeUndefined();
    expect(fetched).toEqual([`https://${META}/.well-known/webauthn`]);
  });

  it.each([
    '192.168.1.1',
    '169.254.169.254',
    '0x7f.1',
    '2130706433',
    'router.lan',
    'nas.local',
    'metadata.google.internal',
    'router.home.arpa',
    'localhost',
  ])('never fetch from %s', async (rpId) => {
    await create(rpId);
    await get(rpId);

    expect(fetched).toEqual([]);
    expect(vault.user.confirmCreate).not.toHaveBeenCalled();
    expect(vault.native.create).toHaveBeenCalled();
  });

  it('cause no fetch on a site the user excluded', async () => {
    await vault.reset({ domain_rules: { mode: 'disabled', domains: [] } });

    await create(META);
    await get(META);

    expect(fetched).toEqual([]);
  });

  it('cause no fetch while the vault is locked, even sent straight to the background', async () => {
    expect(
      (await vault.send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: '482916' } })).success
    ).toBe(true);
    await vault.send({ type: 'LOCK_SECURE_STORAGE' });

    await get(META);
    await vault.chrome.deliver(
      { type: 'LIST_PASSKEYS_FOR_RP', payload: { rpId: META } },
      vault.chrome.contentSender()
    );
    await vault.chrome.deliver(
      { type: 'CHECK_RP_ID', payload: { rpId: META } },
      vault.chrome.contentSender()
    );

    expect(fetched).toEqual([]);
  });

  it('are limited to a few lookups per site', async () => {
    for (let n = 0; n < 20; n++) {
      await vault.chrome.deliver(
        { type: 'CHECK_RP_ID', payload: { rpId: `probe${n}.example.com` } },
        vault.chrome.contentSender()
      );
    }

    expect(fetched).toHaveLength(4);
  });
});
