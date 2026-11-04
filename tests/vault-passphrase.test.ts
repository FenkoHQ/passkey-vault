/**
 * A passphrase as the vault's master secret, next to the PINs vaults
 * already have: what is accepted, that it works through setup, change,
 * unlock and removal, and that every page that asks for it takes one.
 */

import { readFileSync } from 'fs';
import { resolve } from 'path';
import { checkVaultSecret, isPin } from '../src/crypto/vault-secret';
import { loadBackground, unlocksWith, useFakeStorage } from './helpers/pin-background';

jest.mock('../src/sync/sync-service', () => ({
  syncService: {
    initialize: jest.fn(async () => {}),
    disconnect: jest.fn(async () => {}),
    requestSync: jest.fn(async () => {}),
    broadcastPasskeyUpdate: jest.fn(async () => {}),
    getStatus: jest.fn(() => ({ connected: false })),
    getDebugLogs: jest.fn(() => []),
    clearDebugLogs: jest.fn(),
  },
}));

const PASSPHRASE = 'correct horse battery staple';

beforeEach(() => {
  useFakeStorage();
});

describe('what the vault accepts as its secret', () => {
  it.each([
    ['a 4-digit PIN', '1234'],
    ['a 6-digit PIN', '482916'],
    ['a 20-digit PIN', '12345678901234567890'],
    ['an 8-character passphrase', 'abcd efg'],
    ['a passphrase of words', PASSPHRASE],
    ['a passphrase in another script', 'пароль из слов'],
    ['emoji, counted as characters', '🔑🔑🔑🔑🔑🔑🔑🔑'],
    ['256 characters', 'x'.repeat(256)],
  ])('accepts %s', (_label, secret) => {
    expect(checkVaultSecret(secret)).toBeNull();
  });

  it.each([
    ['a 3-digit PIN', '123', 'too-short'],
    ['a short password with letters', 'abc123', 'too-short'],
    ['7 characters', 'abcdefg', 'too-short'],
    ['only spaces', '        ', 'too-short'],
    ['nothing', '', 'too-short'],
    ['not a string', 1234, 'too-short'],
    ['257 characters', 'x'.repeat(257), 'too-long'],
  ])('rejects %s', (_label, secret, problem) => {
    expect(checkVaultSecret(secret)).toBe(problem);
  });

  it('tells a PIN from a passphrase', () => {
    expect(isPin('0123')).toBe(true);
    expect(isPin('０１２３')).toBe(false); // full-width digits are not a PIN
    expect(isPin('12 34')).toBe(false);
  });
});

describe('a vault locked with a passphrase', () => {
  it('sets up, locks and unlocks with the passphrase', async () => {
    const { send } = await loadBackground();

    const setup = await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PASSPHRASE } });

    expect(setup.success).toBe(true);
    expect(await unlocksWith(send, PASSPHRASE)).toBe(true);
    expect(await unlocksWith(send, 'correct horse battery stapler')).toBe(false);
    expect(await unlocksWith(send, PASSPHRASE.toUpperCase())).toBe(false);
  });

  it('unlocks whichever way the accents were typed', async () => {
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: 'crème brûlée au café' } });

    expect(await unlocksWith(send, 'crème brûlée au café')).toBe(true);
  });

  it('changes from a PIN to a passphrase and back', async () => {
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: '1234' } });

    const toPassphrase = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: '1234', newPassword: PASSPHRASE },
    });
    expect(toPassphrase.success).toBe(true);
    expect(await unlocksWith(send, '1234')).toBe(false);
    expect(await unlocksWith(send, PASSPHRASE)).toBe(true);

    const toLongPin = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: PASSPHRASE, newPassword: '0123456789012' },
    });
    expect(toLongPin.success).toBe(true);
    expect(await unlocksWith(send, '0123456789012')).toBe(true);
  });

  it('removes the passphrase with the passphrase', async () => {
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PASSPHRASE } });

    const removed = await send({
      type: 'REMOVE_MASTER_PASSWORD',
      payload: { currentPassword: PASSPHRASE },
    });

    expect(removed.success).toBe(true);
    expect((await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isSetup).toBe(false);
  });

  it('refuses a secret that is too short or too long, at setup and on change', async () => {
    const { send } = await loadBackground();

    for (const password of ['abc123', '123', 'x'.repeat(257)]) {
      const setup = await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password } });
      expect(setup.success).toBe(false);
    }
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PASSPHRASE } });
    const change = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: PASSPHRASE, newPassword: 'abc123' },
    });
    expect(change).toMatchObject({ success: false, error: expect.stringMatching(/passphrase/) });
    expect(await unlocksWith(send, PASSPHRASE)).toBe(true);
  });
});

describe('every page that asks for the secret', () => {
  const page = (name: string) => {
    const doc = document.implementation.createHTMLDocument('');
    doc.documentElement.innerHTML = readFileSync(resolve('src/ui', name), 'utf8');
    return doc;
  };
  const fields: Array<[string, string[]]> = [
    ['popup.html', ['unlock-password', 'setup-password', 'setup-password-confirm']],
    [
      'options.html',
      ['set-pw', 'set-pw-confirm', 'change-pw-current', 'change-pw-new', 'change-pw-confirm'],
    ],
  ];

  it.each(fields)('%s takes a passphrase in every secret field', (name, ids) => {
    const doc = page(name);
    for (const id of ids) {
      const input = doc.getElementById(id) as HTMLInputElement;
      expect(input).not.toBeNull();
      expect(input.type).toBe('password');
      expect(input.getAttribute('inputmode')).toBeNull();
      expect(input.getAttribute('pattern')).toBeNull();
      expect(Number(input.getAttribute('maxlength') ?? Infinity)).toBeGreaterThanOrEqual(256);
    }
  });

  it.each(['popup.html', 'options.html'])('%s explains what a short PIN does not stop', (name) => {
    expect(page(name).querySelector('[data-i18n="vaultSecretHint"]')).not.toBeNull();
  });

  it('checks the secret with the rule the background enforces', () => {
    for (const file of ['src/ui/popup.ts', 'src/ui/options.ts']) {
      const source = readFileSync(resolve(file), 'utf8');
      expect(source).toContain('checkVaultSecret(');
      expect(source).not.toMatch(/\\d\{4,12\}/);
    }
  });
});
