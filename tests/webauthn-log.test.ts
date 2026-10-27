/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * The WebAuthn event log says which sites the user signed in to, and with
 * which passkey. With a PIN set that is otherwise only inside the encrypted
 * vault, so the log must not be written to disk, must not be kept unless the
 * user turned debug logging on, and must not be readable while locked.
 */

import { setupVault, vaultReady } from './helpers/harness';
import { authenticate, register } from './helpers/ceremony';

const vault = setupVault('https://example.com/login');
const PIN = '482916';
const DEBUG_ON = { debug_logging_enabled: true };

beforeAll(() => vaultReady(vault));
beforeEach(async () => {
  await vault.reset();
  vault.goto('https://example.com/login');
});

const sessionLog = () => vault.chrome.sessionArea.data.webauthn_log as any[] | undefined;

describe('the WebAuthn log', () => {
  it('records nothing anywhere while debug logging is off', async () => {
    const registration = await register({
      user: { id: 'dXNlcg', name: 'alice@example.com', displayName: 'Alice' },
    });
    await authenticate(registration);
    await vault.settle();

    expect(vault.storage.webauthn_log).toBeUndefined();
    expect(sessionLog()).toBeUndefined();
    expect((await vault.send({ type: 'GET_WEBAUTHN_LOG' })).logs).toEqual([]);
  });

  it('keeps entries in session memory only, without the account name', async () => {
    await vault.reset(DEBUG_ON);
    const registration = await register({
      user: { id: 'dXNlcg', name: 'alice@example.com', displayName: 'Alice' },
    });
    await authenticate(registration);
    await vault.settle();

    expect(vault.storage.webauthn_log).toBeUndefined();
    const { logs } = await vault.send({ type: 'GET_WEBAUTHN_LOG' });
    expect(logs.map((entry: any) => entry.category)).toEqual(['CREATE', 'GET']);
    expect(logs[0].data).toEqual({ rpId: 'example.com', credentialId: registration.record.id });
    expect(JSON.stringify(sessionLog())).not.toContain('alice');
    expect(JSON.stringify(logs)).not.toContain('alice');
  });

  it('survives a service worker restart, as session storage does', async () => {
    await vault.reset(DEBUG_ON);
    await register();
    await vault.restartWorker();

    expect((await vault.send({ type: 'GET_WEBAUTHN_LOG' })).logs).toHaveLength(1);
  });

  it('is cleared when debug logging is turned off', async () => {
    await vault.reset(DEBUG_ON);
    await register();

    await vault.send({ type: 'SET_DEBUG_LOGGING', payload: { enabled: false } });

    expect((await vault.send({ type: 'GET_WEBAUTHN_LOG' })).logs).toEqual([]);
    expect(sessionLog()).toBeUndefined();
  });

  it('is not handed out while the vault is locked, and is cleared by locking', async () => {
    await vault.reset(DEBUG_ON);
    expect(
      (await vault.send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } })).success
    ).toBe(true);
    await register();
    expect((await vault.send({ type: 'GET_WEBAUTHN_LOG' })).logs).toHaveLength(1);

    await vault.send({ type: 'LOCK_SECURE_STORAGE' });

    expect(await vault.send({ type: 'GET_WEBAUTHN_LOG' })).toMatchObject({
      success: false,
      code: 'VAULT_LOCKED',
    });
    expect(sessionLog()).toBeUndefined();
  });

  it('removes the log earlier builds kept in chrome.storage.local', async () => {
    await vault.reset({
      webauthn_log: [
        {
          timestamp: 1,
          level: 'info',
          category: 'GET',
          message: 'Signed assertion for bank.example',
          data: { rpId: 'bank.example', credentialId: 'abc', user: 'alice' },
        },
      ],
    });

    expect(vault.storage.webauthn_log).toBeUndefined();
  });

  it('is not readable by a web page', async () => {
    await vault.reset(DEBUG_ON);
    await register();

    const response = await vault.chrome.deliver(
      { type: 'GET_WEBAUTHN_LOG' },
      vault.chrome.contentSender()
    );

    expect(response).toMatchObject({ success: false });
    expect(JSON.stringify(response)).not.toContain('example.com');
  });
});
