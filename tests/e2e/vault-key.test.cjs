// End-to-end: the vault key in the built extension, with the production KDF.
// A vault written the way builds before KDF records wrote it is unlocked
// through the popup, upgraded to scrypt in the real MV3 service worker, moved
// to a passphrase in Options, unlocked with it, and removed; then a fresh
// vault is set up with a passphrase. Prints how long an unlock and a backup
// take in the worker.
//
//   npm run build:chrome && node tests/e2e/vault-key.test.cjs
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');

const DIST = path.resolve(__dirname, '../../dist');
const PIN = '482916';
const PASSPHRASE = 'tangerine orbit velvet canyon';

const PASSKEY = {
  id: 'cred-legacy',
  credentialId: 'cred-legacy',
  type: 'public-key',
  rpId: 'legacy.example',
  origin: 'https://legacy.example',
  user: { name: 'old@legacy.example', displayName: 'Old' },
  publicKey: 'BASE64-PUBLIC-KEY',
  privateKey: 'BASE64-PRIVATE-KEY',
  createdAt: 1700000000000,
  counter: 1,
  backupEligible: true,
  backupState: true,
  backupSource: 'created',
};

let context;
let worker;
let extensionId;
const consoleErrors = [];
const timings = {};

before(async () => {
  assert.ok(fs.existsSync(path.join(DIST, 'manifest.json')), 'run npm run build:chrome first');
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fenko-vault-e2e-key-'));
  context = await chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium',
    headless: true,
    args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`],
  });
  worker = context.serviceWorkers()[0] || (await context.waitForEvent('serviceworker'));
  extensionId = new URL(worker.url()).host;

  // A PIN'd vault as earlier builds left it: PBKDF2-SHA256 (100k) over the
  // PIN and passext_encryption_salt, values sealed with AES-256-GCM.
  await worker.evaluate(
    async ([pin, passkey]) => {
      const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const material = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(pin),
        'PBKDF2',
        false,
        ['deriveKey']
      );
      const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );
      const seal = async (text) => {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          key,
          new TextEncoder().encode(text)
        );
        return { data: b64(data), iv: b64(iv), salt: '', version: '2.0' };
      };
      await chrome.storage.local.set({
        passext_encryption_salt: b64(salt),
        passext_master_key_check: await seal('passkey-vault-check'),
        passext_encrypted_passkeys: await seal(JSON.stringify([passkey])),
      });
    },
    [PIN, PASSKEY]
  );
});

after(async () => {
  // Message round trips from the popup, so mostly the KDF in the worker.
  console.log('scrypt in the MV3 service worker (ms):', JSON.stringify(timings));
  await context?.close();
});

async function openPage(name) {
  const page = await context.newPage();
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(`${name}: ${msg.text()}`);
  });
  page.on('pageerror', (error) => consoleErrors.push(`${name}: ${error}`));
  await page.goto(`chrome-extension://${extensionId}/${name}`);
  return page;
}

const stored = (keys) => worker.evaluate((k) => chrome.storage.local.get(k), keys);

/** Type the secret into the popup's lock screen and wait for the vault list. */
async function unlockInPopup(popup, secret) {
  await popup.locator('#lock-screen').waitFor({ state: 'visible' });
  await popup.fill('#unlock-password', secret);
  await popup.click('#unlock-btn');
  await popup.locator('#main-container').waitFor({ state: 'visible' });
}

/** Lock from an unlocked popup once it has loaded the vault, then show its lock screen. */
async function lockAndReload(popup) {
  await popup.locator('.passkey-item').first().waitFor({ state: 'visible' });
  await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'LOCK_SECURE_STORAGE' }));
  await popup.reload();
  await popup.locator('#lock-screen').waitFor({ state: 'visible' });
}

/** The unlock message's round trip, without the popup's rendering. */
async function timeUnlockMessage(page, secret) {
  return page.evaluate(async (password) => {
    await chrome.runtime.sendMessage({ type: 'LOCK_SECURE_STORAGE' });
    const started = performance.now();
    const reply = await chrome.runtime.sendMessage({
      type: 'UNLOCK_SECURE_STORAGE',
      payload: { password },
    });
    return reply.success ? Math.round(performance.now() - started) : -1;
  }, secret);
}

test('unlocks a vault from before KDF records and upgrades its key to scrypt', async () => {
  const popup = await openPage('popup.html');
  await unlockInPopup(popup, PIN);

  await popup.locator('.passkey-item', { hasText: 'legacy.example' }).waitFor();
  const after = await stored(['passext_vault_kdf', 'passext_encryption_salt']);
  assert.equal(after.passext_vault_kdf.kdf, 'scrypt');
  assert.deepEqual(after.passext_vault_kdf.params, { N: 131072, r: 8, p: 1 });
  assert.equal(after.passext_encryption_salt, undefined);
  await popup.close();
});

test('rejects a wrong PIN on the upgraded vault, then opens with the right one', async () => {
  const popup = await openPage('popup.html');
  await lockAndReload(popup);

  await popup.fill('#unlock-password', '000000');
  await popup.click('#unlock-btn');
  await popup.locator('#unlock-error').waitFor({ state: 'visible' });
  assert.match(await popup.locator('#unlock-error').textContent(), /Wrong PIN or passphrase/);

  await unlockInPopup(popup, PIN);
  await popup.locator('.passkey-item', { hasText: 'legacy.example' }).waitFor();
  timings.unlock = await timeUnlockMessage(popup, PIN);
  assert.ok(timings.unlock > 0);
  await popup.close();
});

test('changes the PIN to a passphrase in Options and unlocks with it in the popup', async () => {
  const options = await openPage('options.html');
  await options.click('.nav-item[data-section="security"]');
  await options.locator('#master-pw-change').waitFor({ state: 'visible' });
  assert.match(
    await options.locator('#master-pw-change [data-i18n="vaultSecretHint"]').textContent(),
    /copy of your browser profile/
  );
  await options.fill('#change-pw-current', PIN);
  await options.fill('#change-pw-new', PASSPHRASE);
  await options.fill('#change-pw-confirm', PASSPHRASE);
  await options.click('#change-pw-btn');
  await options.waitForFunction(() => document.getElementById('change-pw-current').value === '');
  assert.equal(await options.locator('#change-pw-error').isVisible(), false);

  const popup = await openPage('popup.html');
  await lockAndReload(popup);
  await popup.fill('#unlock-password', PIN);
  await popup.click('#unlock-btn');
  await popup.locator('#unlock-error').waitFor({ state: 'visible' });
  await unlockInPopup(popup, PASSPHRASE);
  await popup.locator('.passkey-item', { hasText: 'legacy.example' }).waitFor();
  await popup.close();

  // Remove the lock with the passphrase, which hands the vault back in cleartext.
  options.once('dialog', (dialog) => dialog.accept());
  await options.fill('#change-pw-current', PASSPHRASE);
  await options.click('#remove-pw-btn');
  await options.locator('#master-pw-set').waitFor({ state: 'visible' });
  const left = await stored(null);
  assert.deepEqual(
    Object.keys(left).filter((key) => key.startsWith('passext_')),
    []
  );
  assert.equal(left.passkeys[0].privateKey, PASSKEY.privateKey);
  await options.close();
});

test('sets up a new vault with a passphrase from the popup', async () => {
  await worker.evaluate(() => chrome.storage.local.remove('master_password_setup_skipped'));
  const popup = await openPage('popup.html');
  await popup.locator('#setup-screen').waitFor({ state: 'visible' });
  assert.match(await popup.locator('#setup-screen .auth-note').textContent(), /passphrase/);

  // Too short a passphrase is refused before it reaches the background.
  await popup.fill('#setup-password', 'abc123');
  await popup.fill('#setup-password-confirm', 'abc123');
  await popup.click('#setup-btn');
  await popup.locator('#setup-error').waitFor({ state: 'visible' });

  await popup.fill('#setup-password', PASSPHRASE);
  await popup.fill('#setup-password-confirm', PASSPHRASE);
  await popup.click('#setup-btn');
  await popup.locator('#main-container').waitFor({ state: 'visible' });
  const { passext_vault_kdf: kdf } = await stored(['passext_vault_kdf']);
  assert.equal(kdf.kdf, 'scrypt');

  await lockAndReload(popup);
  await unlockInPopup(popup, PASSPHRASE);
  await popup.close();
});

test('encrypts a backup with scrypt in the worker and decrypts it again', async () => {
  const popup = await openPage('popup.html');
  const result = await popup.evaluate(async (password) => {
    const plaintext = JSON.stringify({ passkeys: [], totpEntries: [] });
    let t = performance.now();
    const enc = await chrome.runtime.sendMessage({
      type: 'ENCRYPT_BACKUP',
      payload: { data: plaintext, password },
    });
    const encryptMs = performance.now() - t;
    t = performance.now();
    const dec = await chrome.runtime.sendMessage({
      type: 'DECRYPT_BACKUP',
      payload: { ...enc.encrypted, password },
    });
    return { enc, dec, plaintext, encryptMs, decryptMs: performance.now() - t };
  }, PASSPHRASE);
  timings.backupEncrypt = Math.round(result.encryptMs);
  timings.backupDecrypt = Math.round(result.decryptMs);
  assert.equal(result.enc.success, true);
  assert.equal(result.enc.encrypted.kdf, 'scrypt');
  assert.deepEqual(result.enc.encrypted.kdfParams, { N: 131072, r: 8, p: 1 });
  assert.deepEqual(result.dec, { success: true, data: result.plaintext });
  await popup.close();
});

test('runs without console errors', () => {
  assert.deepEqual(consoleErrors, []);
});
