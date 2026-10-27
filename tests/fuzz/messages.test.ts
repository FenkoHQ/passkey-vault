/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Fuzzing the background's message interface.
 *
 * Every message type gets seeded garbage: wrong types, missing fields,
 * prototype-polluting keys, huge and empty strings, NaN and Infinity. The
 * worker must answer every message (a listener that throws or never calls
 * sendResponse leaves the popup or page waiting forever), keep the vault's
 * records well-formed, and, for anything that does not delete by design,
 * keep the user's passkey working.
 */

import { setupVault, vaultReady } from '../helpers/harness';
import { authenticate, register } from '../helpers/ceremony';
import { prng } from '../helpers/bytes';

const vault = setupVault('https://example.com/login');

beforeAll(() => vaultReady(vault));
beforeEach(async () => {
  await vault.reset();
  vault.goto('https://example.com/login');
});

const TYPES = [
  'CREATE_PASSKEY',
  'DISCARD_REGISTRATION',
  'GET_PASSKEY',
  'RETRIEVE_PASSKEY',
  'LIST_PASSKEYS',
  'GET_PASSKEYS',
  'LIST_PASSKEYS_FOR_RP',
  'VERIFY_RELATED_ORIGIN',
  'NEEDS_SITE_ICON',
  'SAVE_SITE_ICON',
  'DELETE_PASSKEY',
  'SET_PASSKEY_BACKUP',
  'ENCRYPT_BACKUP',
  'LIST_TOTP_ENTRIES',
  'ADD_TOTP_ENTRY',
  'DELETE_TOTP_ENTRY',
  'GENERATE_TOTP_CODE',
  'NEXT_HOTP_CODE',
  'IMPORT_VAULT',
  'EXPORT_VAULT',
  'CLEAR_VAULT',
  'FACTORY_RESET',
  'GET_UPGRADE_BACKUP_STATUS',
  'COMPLETE_UPGRADE_BACKUP',
  'DECRYPT_BACKUP',
  'ACTIVATE_UI',
  'CREATE_SYNC_CHAIN',
  'JOIN_SYNC_CHAIN',
  'LEAVE_SYNC_CHAIN',
  'GET_SYNC_CHAIN_INFO',
  'REMOVE_SYNC_DEVICE',
  'GET_SYNC_STATUS',
  'TRIGGER_SYNC',
  'GET_SYNC_DEBUG_INFO',
  'GET_SYNC_DEBUG_LOGS',
  'CLEAR_SYNC_DEBUG_LOGS',
  'SETUP_MASTER_PASSWORD',
  'UNLOCK_SECURE_STORAGE',
  'LOCK_SECURE_STORAGE',
  'IS_SECURE_STORAGE_UNLOCKED',
  'RECONCILE_STORAGE',
  'CHANGE_MASTER_PASSWORD',
  'REMOVE_MASTER_PASSWORD',
  'SET_DEBUG_LOGGING',
  'GET_DEBUG_LOGGING',
  'GET_WEBAUTHN_FLAGS',
  'SET_WEBAUTHN_FLAGS',
  'SET_AUTO_LOCK_TIMEOUT',
  'GET_WEBAUTHN_LOG',
  'CLEAR_WEBAUTHN_LOG',
  'NO_SUCH_MESSAGE',
];

/** Types that remove or replace vault contents, or lock it, by design. */
const DESTRUCTIVE = new Set([
  'DELETE_PASSKEY',
  'CLEAR_VAULT',
  'FACTORY_RESET',
  'IMPORT_VAULT',
  'SETUP_MASTER_PASSWORD',
  'LOCK_SECURE_STORAGE',
  'SET_AUTO_LOCK_TIMEOUT',
  'SET_WEBAUTHN_FLAGS',
]);

const FIELDS = [
  'rpId',
  'origin',
  'publicKey',
  'credentialId',
  'selectedPasskeyId',
  'synced',
  'password',
  'currentPassword',
  'newPassword',
  'minutes',
  'flags',
  'enabled',
  'passkeys',
  'totpEntries',
  'backupRepairs',
  'id',
  'entry',
  'otpauthUri',
  'data',
  'iv',
  'salt',
  'mimeType',
  '__proto__',
  'constructor',
];

function garbage(random: () => number, depth = 0): unknown {
  const pick = Math.floor(random() * (depth > 2 ? 12 : 16));
  switch (pick) {
    case 0:
      return undefined;
    case 1:
      return null;
    case 2:
      return random() < 0.5;
    case 3:
      return [0, -1, NaN, Infinity, -Infinity, 1e308, 2 ** 53, -0][Math.floor(random() * 8)];
    case 4:
      return Math.floor(random() * 1e6);
    case 5:
      return '';
    case 6:
      return 'x'.repeat(Math.floor(random() * 5000));
    case 7:
      return ['__proto__', 'constructor', 'toString', 'example.com', '1234', '000000', '%%%', '🔑'][
        Math.floor(random() * 8)
      ];
    case 8:
      return 'https://evil.example/' + Math.floor(random() * 100);
    case 9:
      return 'otpauth://totp/a?secret=' + 'A'.repeat(Math.floor(random() * 40));
    case 10:
      return '0'.repeat(4 + Math.floor(random() * 9));
    case 11:
      return { length: -1 };
    default: {
      if (random() < 0.4) {
        return Array.from({ length: Math.floor(random() * 5) }, () => garbage(random, depth + 1));
      }
      const object: Record<string, unknown> = {};
      const count = Math.floor(random() * 6);
      for (let i = 0; i < count; i++) {
        object[FIELDS[Math.floor(random() * FIELDS.length)]] = garbage(random, depth + 1);
      }
      return object;
    }
  }
}

function message(type: string, random: () => number): Record<string, unknown> {
  const shape = Math.floor(random() * 4);
  if (shape === 0) return { type };
  if (shape === 1) return { type, payload: garbage(random) };
  const payload: Record<string, unknown> = {};
  for (const field of FIELDS) if (random() < 0.3) payload[field] = garbage(random);
  return {
    type,
    payload,
    deviceName: garbage(random),
    mnemonic: garbage(random),
    wordCount: garbage(random),
  };
}

async function answered(promise: Promise<unknown>, ms = 5000): Promise<unknown> {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`no answer within ${ms}ms`)), ms)),
  ]);
}

describe.each(TYPES)('%s with garbage', (type) => {
  it('always answers and leaves the vault well-formed', async () => {
    const registration = await register();
    const random = prng(type.split('').reduce((h, c) => (h * 31 + c.charCodeAt(0)) >>> 0, 7));

    for (let i = 0; i < 25; i++) {
      const response = await answered(vault.send(message(type, random)));
      expect(typeof response === 'object' && response !== null).toBe(true);
    }

    const list: any = await answered(vault.send({ type: 'LIST_PASSKEYS' }));
    if (list.success) {
      for (const record of list.passkeys) {
        expect(record).toEqual(
          expect.objectContaining({ id: expect.any(String), rpId: expect.any(String) })
        );
      }
    }
    if (!DESTRUCTIVE.has(type)) {
      expect(list.passkeys.map((p: any) => p.credentialId)).toContain(registration.record.id);
      await authenticate(registration, {}, { strictCounter: false });
    }
  });
});
