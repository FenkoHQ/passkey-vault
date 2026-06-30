#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const root = path.join(__dirname, '..');
const [zipPathArg, targetArg] = process.argv.slice(2);

if (!zipPathArg || !targetArg) {
  console.error('Usage: node scripts/validate-package.js <zip-path> <chrome|firefox>');
  process.exit(1);
}

const zipPath = path.resolve(root, zipPathArg);
const target = targetArg.toLowerCase();
const validTargets = new Set(['chrome', 'firefox']);

if (!validTargets.has(target)) {
  console.error(`Invalid target "${targetArg}". Expected chrome or firefox.`);
  process.exit(1);
}

if (!fs.existsSync(zipPath)) {
  console.error(`Package not found: ${zipPath}`);
  process.exit(1);
}

function readZipEntry(entry) {
  return execFileSync('unzip', ['-p', zipPath, entry]);
}

function hash(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertPng(buffer, entry) {
  const pngSignature = '89504e470d0a1a0a';
  assert(buffer.subarray(0, 8).toString('hex') === pngSignature, `${entry} is not a PNG`);
}

function main() {
  execFileSync('unzip', ['-t', zipPath], { stdio: 'pipe' });

  const entries = new Set(
    execFileSync('unzip', ['-Z1', zipPath], { encoding: 'utf8' })
      .split('\n')
      .map((entry) => entry.trim())
      .filter(Boolean)
  );

  const requiredFiles = [
    'manifest.json',
    'background.js',
    'content.js',
    'webauthn-inject.js',
    'popup.html',
    'popup.js',
    'popup.css',
    'import.html',
    'import.js',
    'emergency.html',
    'emergency-ui.js',
    'sync-setup.html',
    'sync-setup.js',
    'sync-settings.html',
    'sync-settings.js',
    'options.html',
    'options.js',
    'options.css',
    '_locales/en/messages.json',
    'icons/icon16.png',
    'icons/icon48.png',
    'icons/icon128.png',
  ];

  for (const file of requiredFiles) {
    assert(entries.has(file), `Missing required package file: ${file}`);
  }

  const sourceLocalesDir = path.join(root, 'src', '_locales');
  const allowedEntries = new Set([...requiredFiles, 'icons/', '_locales/']);
  for (const locale of fs.readdirSync(sourceLocalesDir)) {
    allowedEntries.add(`_locales/${locale}/`);
    allowedEntries.add(`_locales/${locale}/messages.json`);
  }

  const sourceFontsDir = path.join(root, 'src', 'assets', 'fonts');
  if (fs.existsSync(sourceFontsDir)) {
    allowedEntries.add('fonts/');
    for (const font of fs.readdirSync(sourceFontsDir)) {
      allowedEntries.add(`fonts/${font}`);
    }
  }
  for (const entry of entries) {
    assert(allowedEntries.has(entry), `Unexpected package file: ${entry}`);
  }

  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const manifest = JSON.parse(readZipEntry('manifest.json').toString('utf8'));
  const enMessages = JSON.parse(readZipEntry('_locales/en/messages.json').toString('utf8'));

  assert(
    manifest.version === pkg.version,
    `Manifest version ${manifest.version} != ${pkg.version}`
  );
  if (target === 'chrome') {
    assert(
      manifest.version_name === pkg.version,
      `Manifest version_name ${manifest.version_name} != ${pkg.version}`
    );
  } else {
    // Firefox/AMO doesn't support version_name; the build omits it.
    assert(
      manifest.version_name === undefined,
      `Firefox manifest should not set version_name (got ${manifest.version_name})`
    );
  }
  assert(manifest.name === '__MSG_appName__', `Unexpected manifest name: ${manifest.name}`);
  assert(
    enMessages.appName?.message === 'Fenko Vault | Passkey and MFA Manager',
    `Unexpected localized app name: ${enMessages.appName?.message}`
  );
  assert(manifest.icons?.['16'] === 'icons/icon16.png', 'Manifest icon16 path mismatch');
  assert(manifest.icons?.['48'] === 'icons/icon48.png', 'Manifest icon48 path mismatch');
  assert(manifest.icons?.['128'] === 'icons/icon128.png', 'Manifest icon128 path mismatch');

  if (target === 'chrome') {
    assert(
      manifest.background?.service_worker === 'background.js',
      'Chrome service worker mismatch'
    );
  } else {
    assert(
      manifest.background?.scripts?.includes('background.js'),
      'Firefox background script mismatch'
    );
  }

  for (const size of [16, 48, 128]) {
    const entry = `icons/icon${size}.png`;
    const packagedIcon = readZipEntry(entry);
    const sourceIcon = fs.readFileSync(path.join(root, 'src', 'icons', `icon${size}.png`));
    assertPng(packagedIcon, entry);
    assert(packagedIcon.length === sourceIcon.length, `${entry} size differs from src/icons`);
    assert(hash(packagedIcon) === hash(sourceIcon), `${entry} hash differs from src/icons`);
  }

  console.log(`Package OK: ${path.relative(root, zipPath)} (${target})`);
}

try {
  main();
} catch (error) {
  console.error(`Package validation failed: ${error.message}`);
  process.exit(1);
}
