#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
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

function getVersionFromPackage() {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
  const version = pkg.version;
  if (!/^\d+(\.\d+){0,3}$/.test(version)) {
    throw new Error(`Invalid package version for browser manifest: ${version}`);
  }
  return { version, versionName: version };
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
  manifest.version_name = versionName;

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
`);
  }
}

main().catch((err) => {
  console.error('Build failed:', err);
  process.exit(1);
});
