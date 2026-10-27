// End-to-end smoke test: loads the built Chrome extension into a real Chromium
// and drives the popup. Jest's jsdom suite cannot see manifest permissions, the
// extension CSP, or the popup bundle actually running, which is exactly where a
// release breaks.
//
//   npm run build:chrome && npm run test:e2e
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');

const DIST = path.resolve(__dirname, '../../dist');

// 1x1 opaque PNG, stands in for a captured site icon.
const ICON_PNG =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

const PASSKEYS = [
  {
    id: 'cred-google',
    credentialId: 'cred-google',
    type: 'public-key',
    rpId: 'google.com',
    origin: 'https://google.com',
    user: { name: 'alim@fenko.nz', displayName: 'Ali' },
    publicKey: 'BASE64-PUBLIC-KEY',
    privateKey: 'BASE64-PRIVATE-KEY-MUST-NOT-LEAVE',
    createdAt: 1757000000000,
    counter: 3,
  },
  {
    id: 'cred-mitre',
    credentialId: 'cred-mitre',
    type: 'public-key',
    rpId: 'cveform-api.mitre.org',
    origin: 'https://cveform-api.mitre.org',
    user: { name: 'alim@fenko.nz', displayName: 'Ali' },
    publicKey: 'BASE64-PUBLIC-KEY-2',
    privateKey: 'BASE64-PRIVATE-KEY-MUST-NOT-LEAVE',
    createdAt: 1749000000000,
    counter: 1,
  },
];

function base32ToBytes(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const out = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of text) {
    buffer = (buffer << 5) | alphabet.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return out;
}

let context;
let popup;
let worker;
const consoleErrors = [];

before(async () => {
  assert.ok(fs.existsSync(path.join(DIST, 'manifest.json')), 'run npm run build:chrome first');

  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fenko-vault-e2e-'));
  context = await chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium',
    headless: true,
    args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`],
  });

  worker = context.serviceWorkers()[0] || (await context.waitForEvent('serviceworker'));
  const extensionId = new URL(worker.url()).host;

  // Seed the unencrypted display copies the popup reads when no PIN is set.
  await worker.evaluate(
    async ([passkeys, iconDataUrl]) => {
      await chrome.storage.local.set({
        passkeys,
        site_icons: { 'google.com': { dataUrl: iconDataUrl, updatedAt: Date.now() } },
        // Skip the PIN onboarding screen the popup shows on a fresh profile.
        master_password_setup_skipped: true,
      });
    },
    [PASSKEYS, ICON_PNG]
  );

  popup = await context.newPage();

  // Clipboard permissions cannot be granted to an extension origin, so record
  // what the popup writes instead of reading the real clipboard back.
  await popup.addInitScript(() => {
    window.__copied = null;
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (text) => {
          window.__copied = text;
        },
      },
    });
  });

  popup.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  popup.on('pageerror', (error) => consoleErrors.push(String(error)));

  await popup.goto(`chrome-extension://${extensionId}/popup.html`);
  await popup.waitForSelector('.passkey-item');
});

after(async () => {
  await context?.close();
});

test('lists the stored passkeys', async () => {
  const rows = await popup.locator('.passkey-rp').allTextContents();
  assert.deepEqual(rows.sort(), ['cveform-api.mitre.org', 'google.com']);
});

test('labels each row icon with its site, not the entry type', async () => {
  const title = await popup
    .locator('.passkey-item', { hasText: 'google.com' })
    .locator('.vault-item-icon')
    .getAttribute('title');
  assert.equal(title, 'google.com');
});

test('shows a stored site icon in place of the placeholder glyph', async () => {
  const row = popup.locator('.passkey-item', { hasText: 'google.com' });
  await row.locator('.vault-item-icon img.site-icon').waitFor({ state: 'attached' });
  assert.equal(
    await row.locator('.vault-item-icon').evaluate((el) => el.querySelector('svg') === null),
    true
  );

  // A row with no captured icon keeps the glyph.
  const bare = popup.locator('.passkey-item', { hasText: 'cveform-api.mitre.org' });
  assert.equal(await bare.locator('.vault-item-icon svg').count(), 1);
});

test('hides the copy control until the row is expanded', async () => {
  const row = popup.locator('.passkey-item', { hasText: 'google.com' });
  assert.equal(await row.locator('.passkey-copy').isVisible(), false);

  await row.locator('.expand-btn').click();
  assert.equal(await row.locator('.passkey-copy').isVisible(), true);
});

test('warns before copying and copies nothing on cancel', async () => {
  const row = popup.locator('.passkey-item', { hasText: 'google.com' });
  await row.locator('.passkey-copy').click();

  const modal = popup.locator('#confirm-modal');
  await modal.waitFor({ state: 'visible' });
  assert.match(await modal.locator('.modal-message').textContent(), /clipboard/i);

  await modal.locator('.modal-cancel').click();
  assert.equal(await popup.evaluate(() => window.__copied), null);
});

test('copies metadata but never the private key once confirmed', async () => {
  const row = popup.locator('.passkey-item', { hasText: 'google.com' });
  await row.locator('.passkey-copy').click();
  await popup.locator('#confirm-modal .modal-confirm').click();

  const copied = JSON.parse(await popup.evaluate(() => window.__copied));
  assert.equal(copied.rpId, 'google.com');
  assert.equal(copied.publicKey, 'BASE64-PUBLIC-KEY');
  assert.equal('privateKey' in copied, false);
});

test('explains what is wrong with a mistyped setup key', async () => {
  await popup.locator('#add-totp-btn').click();
  const dialog = popup.locator('.modal-overlay', { has: popup.locator('#totp-uri-input') });
  await dialog.locator('#totp-uri-input').fill('kpvg 0irr 6z5n 4nzr');
  assert.equal(await dialog.locator('#totp-key-details').isVisible(), false);

  await dialog.locator('#totp-add-save').click();
  await dialog.locator('#totp-add-error').waitFor({ state: 'visible' });
  assert.match(await dialog.locator('#totp-add-error').textContent(), /2–7.*: 0$/);
  await dialog.locator('#totp-add-cancel').click();
});

test('adds a 2FA code from a bare setup key once it has a name', async () => {
  await popup.locator('#add-totp-btn').click();
  const dialog = popup.locator('.modal-overlay', { has: popup.locator('#totp-uri-input') });
  // The way services print keys for manual entry: grouped and lowercase.
  await dialog.locator('#totp-uri-input').fill('kpvg zirr 6z5n 4nzr qdqn loiy jqm2 kg5z');
  await dialog.locator('#totp-key-details').waitFor({ state: 'visible' });

  await dialog.locator('#totp-add-save').click();
  assert.match(await dialog.locator('#totp-add-error').textContent(), /service name/);

  await dialog.locator('#totp-key-issuer').fill('Example');
  await dialog.locator('#totp-key-account').fill('ali@example.com');
  await dialog.locator('#totp-add-save').click();
  await dialog.waitFor({ state: 'detached' });

  await popup.locator('.totp-item', { hasText: 'Example' }).waitFor();
  const stored = await worker.evaluate(async () => {
    const { totp_entries: entries } = await chrome.storage.local.get('totp_entries');
    return entries;
  });
  assert.equal(stored.length, 1);
  assert.equal(stored[0].issuer, 'Example');
  assert.equal(stored[0].account, 'ali@example.com');
  assert.equal(stored[0].algorithm, 'SHA1');
  assert.equal(stored[0].digits, 6);
  assert.equal(stored[0].period, 30);
  assert.equal(
    stored[0].secretB64,
    Buffer.from(base32ToBytes('KPVGZIRR6Z5N4NZRQDQNLOIYJQM2KG5Z')).toString('base64')
  );
});

test('renders the popup without console errors', () => {
  assert.deepEqual(consoleErrors, []);
});
