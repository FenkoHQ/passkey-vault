#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const esbuild = require('esbuild');

const args = process.argv.slice(2);
const targetArg = args.find((arg) => arg.startsWith('--target='));
const target = targetArg ? targetArg.split('=')[1] : 'chrome';

const validTargets = ['chrome', 'firefox', 'all'];
if (!validTargets.includes(target)) {
  console.error(`Invalid target: ${target}. Valid targets: ${validTargets.join(', ')}`);
  process.exit(1);
}

const targets = target === 'all' ? ['chrome', 'firefox'] : [target];

// The release workflow sets this for the packages it uploads to the stores.
// Every other build is a development build.
const isRelease = process.env.PASSKEY_VAULT_RELEASE === '1';

// Chrome gives an unpacked extension an ID made from its folder's path unless
// the manifest has a key, and keeps the extension's storage, vault included,
// under that ID, so a build loaded from a new folder started with an empty
// vault. Development builds carry this public key instead, which makes every
// one of them opnaemnnjkoolijgdldhjfinpjmhkagi wherever it is loaded from. Its
// private half was not kept: loading unpacked needs only this, and no package
// can be signed as this ID. Store packages keep the IDs the stores gave them.
const DEV_PUBLIC_KEY =
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0oKeBOcHT2frHj4npujFfCF/1FfQd6Q9e+6jVheXDhypA9aVkGuAjxcEoTDo/mAAVU8dd/YsfE3Uihq2KQPPWw84l8JgaHKPSnIAjGc3MtUKiYAkjT70OFbpHY0g7O5yJMqE7DHR96CJuXY98CZv/kekSwHqmZIgTVoOPHCls3k+Z36WJGLhCFq55B8HsOKgNB3LuMWW8MH6kApBM8/5t0r450d8mUX8PvSKxAGAY6RnN6fdaQBldV4FXQCXKG3rFD62WVjaDNPdKkKqv35Eia5fRszNodQlJUxErX0/Q49jV3ryM2uYxbcefwLFrLhoaEJqqA1lcXrOlxGtLkH9uwIDAQAB';

// The ID Chrome derives from a manifest key: the first 32 hex digits of the
// key's SHA-256, each written as a letter from a to p.
function chromeExtensionId(key) {
  const hex = crypto.createHash('sha256').update(Buffer.from(key, 'base64')).digest('hex');
  return [...hex.slice(0, 32)]
    .map((digit) => String.fromCharCode(97 + parseInt(digit, 16)))
    .join('');
}

function getVersionFromPackage() {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
  const version = pkg.version;
  if (!/^\d+(\.\d+){0,3}$/.test(version)) {
    throw new Error(`Invalid package version for browser manifest: ${version}`);
  }
  // Chrome shows version_name on chrome://extensions, so a development build
  // names its commit there, as in 0.12.0+2d873fb.
  const commit = isRelease ? null : getCommit();
  return { version, versionName: commit ? `${version}+${commit}` : version };
}

// HEAD's short hash, plus .dirty when tracked files have uncommitted changes.
// Null outside a git checkout, such as a source archive.
function getCommit() {
  const git = (...gitArgs) =>
    execFileSync('git', gitArgs, {
      cwd: __dirname,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  try {
    const hash = git('rev-parse', '--short', 'HEAD');
    return git('status', '--porcelain', '--untracked-files=no') ? `${hash}.dirty` : hash;
  } catch {
    return null;
  }
}

async function main() {
  for (const browserTarget of targets) {
    await buildForTarget(browserTarget);
  }
}

async function buildForTarget(browserTarget) {
  const isFirefox = browserTarget === 'firefox';
  const distDir = isFirefox ? 'dist-firefox' : 'dist';

  console.log(`\n🏗️  Building Passkey Vault for ${browserTarget.toUpperCase()}...\n`);

  const { version, versionName } = getVersionFromPackage();
  console.log(`📌 Version: ${versionName} (manifest: ${version})`);

  console.log(`🧹 Cleaning ${distDir} directory...`);
  if (fs.existsSync(distDir)) {
    fs.rmSync(distDir, { recursive: true, force: true });
  }
  fs.mkdirSync(distDir, { recursive: true });

  console.log('📦 Bundling with esbuild...');

  const commonOptions = {
    bundle: true,
    minify: false,
    sourcemap: false,
    target: ['chrome88', 'firefox109'],
    format: 'iife',
    platform: 'browser',
    // Firefox's `chrome.*` namespace is callback-only; its promise-based APIs
    // live under `browser.*`. The code uses promise-style `chrome.*` throughout
    // (works natively on Chrome MV3), so on Firefox we re-point the global
    // `chrome` at `browser`. No-op on Chrome (browser is undefined) and in the
    // page-world inject script.
    banner: {
      js: "(function(){if(typeof browser!=='undefined'&&typeof globalThis!=='undefined'){try{globalThis.chrome=browser;}catch(e){}}})();",
    },
  };

  try {
    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/background/background.ts'],
      outfile: `${distDir}/background.js`,
    });
    console.log('  ✅ background.js');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/content/content.ts'],
      outfile: `${distDir}/content.js`,
    });

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/ui/passkey-ui.ts'],
      outfile: `${distDir}/passkey-ui.js`,
    });

    const passkeyUiJs = fs.readFileSync(`${distDir}/passkey-ui.js`, 'utf8');
    const contentJs = fs.readFileSync(`${distDir}/content.js`, 'utf8');
    fs.writeFileSync(`${distDir}/content.js`, passkeyUiJs + '\n' + contentJs);
    fs.unlinkSync(`${distDir}/passkey-ui.js`);
    console.log('  ✅ content.js (bundled with passkey-ui)');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/content/webauthn-inject.ts'],
      outfile: `${distDir}/webauthn-inject.js`,
    });
    console.log('  ✅ webauthn-inject.js');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/ui/popup.ts'],
      outfile: `${distDir}/popup.js`,
    });
    console.log('  ✅ popup.js');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/ui/import.ts'],
      outfile: `${distDir}/import.js`,
    });
    console.log('  ✅ import.js');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/ui/emergency-ui.ts'],
      outfile: `${distDir}/emergency-ui.js`,
    });
    console.log('  ✅ emergency-ui.js');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/ui/sync-setup.ts'],
      outfile: `${distDir}/sync-setup.js`,
    });
    console.log('  ✅ sync-setup.js');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/ui/sync-settings.ts'],
      outfile: `${distDir}/sync-settings.js`,
    });
    console.log('  ✅ sync-settings.js');

    await esbuild.build({
      ...commonOptions,
      entryPoints: ['src/ui/options.ts'],
      outfile: `${distDir}/options.js`,
    });
    console.log('  ✅ options.js');
  } catch (error) {
    console.error('❌ Build failed:', error.message);
    process.exit(1);
  }

  console.log('📋 Processing manifest...');
  const manifestFile = isFirefox ? 'src/manifest.firefox.json' : 'src/manifest.json';
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));

  // Set version from git
  manifest.version = version;
  // Firefox/AMO doesn't support version_name (lints as a warning); Chrome does.
  if (!isFirefox) {
    manifest.version_name = versionName;
    if (!isRelease) {
      manifest.key = DEV_PUBLIC_KEY;
    }
  }

  if (isFirefox) {
    manifest.background.scripts = ['background.js'];
    manifest.content_scripts[0].js = ['content.js'];
    manifest.web_accessible_resources[0].resources = ['webauthn-inject.js'];
  } else {
    manifest.background.service_worker = 'background.js';
    manifest.content_scripts[0].js = ['content.js'];
    manifest.web_accessible_resources[0].resources = ['webauthn-inject.js'];
  }

  fs.writeFileSync(`${distDir}/manifest.json`, JSON.stringify(manifest, null, 2));
  console.log('  ✅ manifest.json');

  const iconsDir = path.join(distDir, 'icons');
  fs.mkdirSync(iconsDir, { recursive: true });

  console.log('🎨 Processing icons...');

  const sourceIconsDir = path.join('src', 'icons');
  const iconSizes = [16, 48, 128];

  for (const size of iconSizes) {
    const sourcePath = path.join(sourceIconsDir, `icon${size}.png`);
    const outputPath = path.join(iconsDir, `icon${size}.png`);
    if (!fs.existsSync(sourcePath)) {
      throw new Error(`Missing required icon asset: ${sourcePath}`);
    }
    fs.copyFileSync(sourcePath, outputPath);
  }
  console.log('  ✅ Copied checked-in icons from src/icons');

  console.log('📄 Copying static assets...');

  const localesSourceDir = path.join('src', '_locales');
  if (fs.existsSync(localesSourceDir)) {
    fs.cpSync(localesSourceDir, path.join(distDir, '_locales'), { recursive: true });
    console.log('  ✅ _locales');
  }

  const fontsSourceDir = path.join('src', 'assets', 'fonts');
  if (fs.existsSync(fontsSourceDir)) {
    fs.cpSync(fontsSourceDir, path.join(distDir, 'fonts'), { recursive: true });
    console.log('  ✅ fonts');
  }

  if (fs.existsSync('src/ui/emergency.html')) {
    fs.copyFileSync('src/ui/emergency.html', `${distDir}/emergency.html`);
    console.log('  ✅ emergency.html');
  }

  if (fs.existsSync('src/ui/popup.html')) {
    fs.copyFileSync('src/ui/popup.html', `${distDir}/popup.html`);
    console.log('  ✅ popup.html');
  }

  if (fs.existsSync('src/ui/popup.css')) {
    fs.copyFileSync('src/ui/popup.css', `${distDir}/popup.css`);
    console.log('  ✅ popup.css');
  }

  if (fs.existsSync('src/ui/import.html')) {
    fs.copyFileSync('src/ui/import.html', `${distDir}/import.html`);
    console.log('  ✅ import.html');
  }

  if (fs.existsSync('src/ui/sync-setup.html')) {
    fs.copyFileSync('src/ui/sync-setup.html', `${distDir}/sync-setup.html`);
    console.log('  ✅ sync-setup.html');
  }

  if (fs.existsSync('src/ui/sync-settings.html')) {
    fs.copyFileSync('src/ui/sync-settings.html', `${distDir}/sync-settings.html`);
    console.log('  ✅ sync-settings.html');
  }

  if (fs.existsSync('src/ui/options.html')) {
    fs.copyFileSync('src/ui/options.html', `${distDir}/options.html`);
    console.log('  ✅ options.html');
  }

  if (fs.existsSync('src/ui/options.css')) {
    fs.copyFileSync('src/ui/options.css', `${distDir}/options.css`);
    console.log('  ✅ options.css');
  }

  let totalSize = 0;
  const files = fs
    .readdirSync(distDir)
    .filter((f) => !fs.statSync(path.join(distDir, f)).isDirectory());
  for (const file of files) {
    totalSize += fs.statSync(path.join(distDir, file)).size;
  }
  fs.readdirSync(iconsDir).forEach((file) => {
    totalSize += fs.statSync(path.join(iconsDir, file)).size;
  });

  const localesDir = path.join(distDir, '_locales');
  if (fs.existsSync(localesDir)) {
    for (const locale of fs.readdirSync(localesDir)) {
      const messagesPath = path.join(localesDir, locale, 'messages.json');
      if (fs.existsSync(messagesPath)) {
        totalSize += fs.statSync(messagesPath).size;
      }
    }
  }

  console.log(`\n🎉 ${browserTarget.toUpperCase()} Build Complete!`);
  console.log(`📦 Extension: ${manifest.name} v${versionName}`);
  if (manifest.key) {
    console.log(`🔑 Extension ID: ${chromeExtensionId(manifest.key)}`);
  }
  console.log(`📁 Output: ${distDir}/`);
  console.log(`💾 Total size: ${(totalSize / 1024).toFixed(1)}KB`);

  if (isFirefox) {
    console.log(`
🦊 Ready to install in Firefox!

Installation (Temporary):
1. Open about:debugging#/runtime/this-firefox
2. Click "Load Temporary Add-on..."
3. Select the manifest.json file in the "${distDir}" directory
`);
  } else {
    console.log(`
🚀 Ready to install in Chrome!

Installation:
1. Open chrome://extensions/
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the "${distDir}" directory
${manifest.key ? '\nTo update, load the new build the same way. Remove would delete the vault.\n' : ''}`);
  }
}

main().catch((err) => {
  console.error('Build failed:', err);
  process.exit(1);
});
