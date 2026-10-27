/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Chaos: an attacker.
 *
 * Two attackers matter. A malicious page can post anything it likes to the
 * content script, so the content script must bind every request to the
 * page's real origin. A compromised renderer (a browser exploit in the
 * page's process) can do more: it can send any runtime message the content
 * script could send. Chrome's guidance is to treat content scripts as
 * untrusted for exactly this reason, so the background must not hand a
 * page's process another site's credentials, or the vault itself.
 */

import { EXTENSION_PAGE, setupVault, vaultReady } from '../helpers/harness';
import { outcome, register } from '../helpers/ceremony';
import { EXTENSION_ID, type MessageSender } from '../helpers/fake-chrome';
import { b64url } from '../helpers/bytes';
import { authenticationJSON, requestOptionsFromJSON } from '../helpers/options';

const vault = setupVault('https://bank.example/login');

beforeAll(() => vaultReady(vault));

let bankCredentialId: string;

beforeEach(async () => {
  await vault.reset();
  vault.goto('https://bank.example/login');
  bankCredentialId = (await register()).record.id;
  vault.goto('https://evil.example/');
});

/** The content script of evil.example, as a compromised renderer can impersonate it. */
const EVIL_PAGE: MessageSender = {
  id: EXTENSION_ID,
  url: 'https://evil.example/',
  origin: 'https://evil.example',
  tab: { id: 9, url: 'https://evil.example/' },
  frameId: 0,
};

describe('a malicious page', () => {
  it('cannot claim another origin in a forged request', async () => {
    vault.native.get.mockResolvedValue({ id: 'native' });
    const requestId = 'forged';
    window.dispatchEvent(
      new MessageEvent('message', {
        source: window,
        data: {
          source: 'PASSKEY_VAULT_PAGE',
          type: 'PASSKEY_GET_REQUEST',
          requestId,
          payload: {
            origin: 'https://bank.example',
            publicKey: { rpId: 'bank.example', challenge: b64url(new Uint8Array(32)) },
          },
        },
      })
    );
    await vault.settle();

    expect(vault.user.choosePasskey).not.toHaveBeenCalled();
    const traffic = JSON.stringify(vault.chrome.sentToBackground);
    expect(traffic).not.toContain('GET_PASSKEY"');
  });

  it('cannot get a bank passkey through navigator.credentials', async () => {
    vault.native.get.mockRejectedValue(new DOMException('no', 'SecurityError'));

    const { error } = await outcome(
      navigator.credentials.get({
        publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'bank.example' })),
      })
    );

    expect(error?.name).toBe('SecurityError');
    expect(vault.user.choosePasskey).not.toHaveBeenCalled();
  });
});

describe('a compromised renderer impersonating the content script', () => {
  const privileged: Array<[string, Record<string, unknown>]> = [
    ['EXPORT_VAULT', {}],
    ['LIST_PASSKEYS', {}],
    ['GET_PASSKEYS', {}],
    ['RETRIEVE_PASSKEY', { payload: { publicKey: { rpId: 'bank.example' } } }],
    ['LIST_TOTP_ENTRIES', {}],
    ['DELETE_PASSKEY', { payload: { credentialId: 'x' } }],
    ['CLEAR_VAULT', {}],
    ['FACTORY_RESET', {}],
    ['IMPORT_VAULT', { payload: { passkeys: [] } }],
    ['SET_WEBAUTHN_FLAGS', { payload: { flags: { userVerification: 'never' } } }],
    ['SET_DEBUG_LOGGING', { payload: { enabled: true } }],
    ['GET_SYNC_DEBUG_LOGS', {}],
    ['LOCK_SECURE_STORAGE', {}],
    ['REMOVE_MASTER_PASSWORD', { payload: { currentPassword: '0000' } }],
    ['LEAVE_SYNC_CHAIN', {}],
    ['DECRYPT_BACKUP', { payload: { data: '', iv: '', salt: '', password: 'x' } }],
  ];

  it.each(privileged)('is refused %s', async (type, extra) => {
    const response: any = await vault.send({ type, ...extra }, EVIL_PAGE);

    expect(response?.success).not.toBe(true);
    expect(JSON.stringify(response ?? null)).not.toContain('privateKey');
    // The vault is intact.
    expect((await vault.passkeys()).map((p) => p.credentialId)).toEqual([bankCredentialId]);
  });

  it('cannot list the accounts held for another site', async () => {
    const response: any = await vault.send(
      { type: 'LIST_PASSKEYS_FOR_RP', payload: { rpId: 'bank.example' } },
      EVIL_PAGE
    );

    expect(response?.passkeys ?? []).toEqual([]);
    expect(JSON.stringify(response ?? null)).not.toContain(bankCredentialId);
  });

  it('cannot sign for another site by putting its origin in the payload', async () => {
    const response: any = await vault.send(
      {
        type: 'GET_PASSKEY',
        payload: {
          origin: 'https://bank.example',
          selectedPasskeyId: bankCredentialId,
          publicKey: { rpId: 'bank.example', challenge: b64url(new Uint8Array(32)) },
        },
      },
      EVIL_PAGE
    );

    expect(response?.success).not.toBe(true);
    expect(response?.credential).toBeUndefined();
  });

  it('cannot create a passkey for another site', async () => {
    const response: any = await vault.send(
      {
        type: 'CREATE_PASSKEY',
        payload: {
          origin: 'https://bank.example',
          publicKey: {
            rpId: 'bank.example',
            rp: { name: 'Bank', id: 'bank.example' },
            user: { id: 'AQ', name: 'victim', displayName: 'Victim' },
            challenge: b64url(new Uint8Array(32)),
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          },
        },
      },
      EVIL_PAGE
    );

    expect(response?.success).not.toBe(true);
    expect(await vault.passkeys()).toHaveLength(1);
  });

  it('still lets the extension pages do all of this', async () => {
    const exported: any = await vault.send({ type: 'EXPORT_VAULT' }, EXTENSION_PAGE);

    expect(exported.success).toBe(true);
    expect(exported.passkeys).toHaveLength(1);
  });

  it('still lets the options page, opened in a tab, do all of this', async () => {
    const optionsTab: MessageSender = {
      ...EXTENSION_PAGE,
      url: `${EXTENSION_PAGE.origin}/options.html`,
      tab: { id: 3, url: `${EXTENSION_PAGE.origin}/options.html` },
    };

    const exported: any = await vault.send({ type: 'EXPORT_VAULT' }, optionsTab);

    expect(exported.success).toBe(true);
  });
});

describe('taking back a registration', () => {
  const createFrom = (sender: MessageSender, requestId: string) =>
    vault.send(
      {
        type: 'CREATE_PASSKEY',
        requestId,
        payload: {
          publicKey: {
            rp: { name: 'Evil', id: 'evil.example' },
            user: { id: 'AQ', name: 'me', displayName: 'Me' },
            challenge: b64url(new Uint8Array(32)),
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          },
        },
      },
      sender
    );

  it('works for the tab, frame and origin the passkey was made for', async () => {
    await createFrom(EVIL_PAGE, 'req-1');
    expect(await vault.passkeys()).toHaveLength(2);

    const response: any = await vault.send(
      { type: 'DISCARD_REGISTRATION', requestId: 'req-1' },
      EVIL_PAGE
    );

    expect(response.success).toBe(true);
    expect((await vault.passkeys()).map((p) => p.credentialId)).toEqual([bankCredentialId]);
  });

  it.each([
    ['another tab', { ...EVIL_PAGE, tab: { id: 10, url: 'https://evil.example/' } }],
    ['another frame', { ...EVIL_PAGE, frameId: 3 }],
    [
      'another origin',
      {
        ...EVIL_PAGE,
        url: 'https://other.example/',
        origin: 'https://other.example',
        tab: { id: 9, url: 'https://other.example/' },
      },
    ],
  ])('is refused from %s', async (_label, sender) => {
    await createFrom(EVIL_PAGE, 'req-2');

    const response: any = await vault.send(
      { type: 'DISCARD_REGISTRATION', requestId: 'req-2' },
      sender as MessageSender
    );

    expect(response.success).toBe(false);
    expect(await vault.passkeys()).toHaveLength(2);
  });

  it('cannot remove a passkey made by any other request', async () => {
    const response: any = await vault.send(
      { type: 'DISCARD_REGISTRATION', requestId: 'never-made' },
      EVIL_PAGE
    );

    expect(response.success).toBe(false);
    expect((await vault.passkeys()).map((p) => p.credentialId)).toEqual([bankCredentialId]);
  });

  it('expires after ten minutes', async () => {
    await createFrom(EVIL_PAGE, 'req-3');
    const now = Date.now();
    jest.spyOn(Date, 'now').mockReturnValue(now + 10 * 60 * 1000 + 1);

    const response: any = await vault.send(
      { type: 'DISCARD_REGISTRATION', requestId: 'req-3' },
      EVIL_PAGE
    );
    jest.restoreAllMocks();

    expect(response.success).toBe(false);
    expect(await vault.passkeys()).toHaveLength(2);
  });
});

describe('a frame that lies about where it runs', () => {
  it('is marked cross-origin from the tab Chrome reports, whatever the payload says', async () => {
    vault.goto('https://widget.example/');
    const frame: MessageSender = {
      id: EXTENSION_ID,
      url: 'https://widget.example/embed',
      origin: 'https://widget.example',
      tab: { id: 4, url: 'https://shop.example/checkout' },
      frameId: 12,
    };

    const response: any = await vault.send(
      {
        type: 'CREATE_PASSKEY',
        requestId: 'framed',
        payload: {
          crossOrigin: false,
          publicKey: {
            rp: { name: 'Widget', id: 'widget.example' },
            user: { id: 'AQ', name: 'me', displayName: 'Me' },
            challenge: b64url(new Uint8Array(32)),
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          },
        },
      },
      frame
    );

    const clientData = JSON.parse(atob(response.credential.response.clientDataJSON));
    expect(clientData).toMatchObject({
      origin: 'https://widget.example',
      crossOrigin: true,
      topOrigin: 'https://shop.example',
    });
  });

  it('cannot claim to be cross-origin in a top-level page', async () => {
    const response: any = await vault.send(
      {
        type: 'CREATE_PASSKEY',
        requestId: 'top',
        payload: {
          crossOrigin: true,
          topOrigin: 'https://bank.example',
          publicKey: {
            rp: { name: 'Evil', id: 'evil.example' },
            user: { id: 'AQ', name: 'me', displayName: 'Me' },
            challenge: b64url(new Uint8Array(32)),
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          },
        },
      },
      EVIL_PAGE
    );

    const clientData = JSON.parse(atob(response.credential.response.clientDataJSON));
    expect(clientData.crossOrigin).toBe(false);
    expect(clientData).not.toHaveProperty('topOrigin');
  });
});
