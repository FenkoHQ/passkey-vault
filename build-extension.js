#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const zlib = require('zlib');
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

/**
 * Get version info from git.
 *
 * If HEAD is tagged with a valid semver (e.g., v1.2.3):
 *   - version: "1.2.3"
 *   - versionName: "1.2.3"
 *
 * If HEAD is not tagged, use git describe format (like Go pseudo-versions):
 *   - versionName: "1.2.3-11-g93f5879" (base tag + commits since + short hash)
 *   - version: "1.2.3.11" (for Chrome manifest compatibility)
 */
function getVersionFromGit() {
  try {
    // First, try to get exact tag on current commit
    try {
      const exactTag = execSync('git describe --tags --exact-match 2>/dev/null', {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
      }).trim();

      // Remove 'v' prefix if present
      const versionName = exactTag.startsWith('v') ? exactTag.slice(1) : exactTag;

      // Check if it's a valid Chrome version (1-4 dot-separated integers only)
      if (/^\d+(\.\d+){0,3}$/.test(versionName)) {
        return { version: versionName, versionName };
      }
      // Tag exists but isn't valid for Chrome, fall through to describe
    } catch {
      // No exact tag, continue to git describe
    }

    // Use git describe to get base tag + distance + commit
    const describe = execSync('git describe --tags 2>/dev/null', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();

    // Parse: v1.2.3-11-g93f5879 -> { tag: "1.2.3", distance: 11, hash: "93f5879" }
    const match = describe.match(/^v?(\d+\.\d+\.\d+)-(\d+)-g([a-f0-9]+)$/);
    if (match) {
      const [, baseVersion, distance, hash] = match;
      const versionName = `${baseVersion}-${distance}-${hash}`;
      // Chrome version: append distance as 4th component (1.2.3.11)
      const version = `${baseVersion}.${distance}`;
      return { version, versionName };
    }

    // Fallback: tag exists but doesn't match expected format
    const versionName = describe.startsWith('v') ? describe.slice(1) : describe;
    const commitCount = execSync('git rev-list --count HEAD', { encoding: 'utf8' }).trim();
    return { version: `0.0.${commitCount}`, versionName };
  } catch {
    // No tags at all, use commit count and hash
    const shortHash = execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim();
    const commitCount = execSync('git rev-list --count HEAD', { encoding: 'utf8' }).trim();

    return {
      version: `0.0.${commitCount}`,
      versionName: `0.0.0-${commitCount}-${shortHash}`,
    };
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

  console.log(`\n🏗️  Building PassKey Vault for ${browserTarget.toUpperCase()}...\n`);

  // Get version from git
  const { version, versionName } = getVersionFromGit();
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
    manifest.web_accessible_resources = ['webauthn-inject.js'];
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

  const sourceIcon = 'icon.png';
  const iconSizes = [16, 48, 128];

  if (fs.existsSync(sourceIcon)) {
    try {
      for (const size of iconSizes) {
        const outputPath = path.join(iconsDir, `icon${size}.png`);
        execSync(`convert "${sourceIcon}" -resize ${size}x${size} "${outputPath}"`, {
          stdio: 'pipe',
        });
      }
      console.log('  ✅ Resized icons from icon.png');
    } catch (error) {
      console.warn('  ⚠️  ImageMagick not available, generating placeholder icons');
      generatePlaceholderIcons(iconsDir, iconSizes);
    }
  } else {
    console.warn('  ⚠️  icon.png not found, generating placeholder icons');
    generatePlaceholderIcons(iconsDir, iconSizes);
  }

  function generatePlaceholderIcons(dir, sizes) {
    for (const size of sizes) {
      const png = createMinimalPNG(size, 74, 144, 217);
      fs.writeFileSync(path.join(dir, `icon${size}.png`), png);
    }
  }

  function createMinimalPNG(size, r, g, b) {
    const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

    const ihdr = Buffer.alloc(25);
    ihdr.writeUInt32BE(13, 0);
    ihdr.write('IHDR', 4);
    ihdr.writeUInt32BE(size, 8);
    ihdr.writeUInt32BE(size, 12);
    ihdr.writeUInt8(8, 16);
    ihdr.writeUInt8(2, 17);
    ihdr.writeUInt8(0, 18);
    ihdr.writeUInt8(0, 19);
    ihdr.writeUInt8(0, 20);
    ihdr.writeUInt32BE(zlib.crc32(ihdr.subarray(4, 21)), 21);

    const rawData = Buffer.alloc(size * (1 + size * 3));
    for (let y = 0; y < size; y++) {
      rawData[y * (1 + size * 3)] = 0;
      for (let x = 0; x < size; x++) {
        const offset = y * (1 + size * 3) + 1 + x * 3;
        const cx = size / 2,
          cy = size / 2;
        const dist = Math.sqrt((x - cx) ** 2 + (y - cy) ** 2);
        if (dist < size * 0.4) {
          rawData[offset] = 255;
          rawData[offset + 1] = 255;
          rawData[offset + 2] = 255;
        } else {
          rawData[offset] = r;
          rawData[offset + 1] = g;
          rawData[offset + 2] = b;
        }
      }
    }

    const compressed = zlib.deflateSync(rawData);
    const idat = Buffer.alloc(compressed.length + 12);
    idat.writeUInt32BE(compressed.length, 0);
    idat.write('IDAT', 4);
    compressed.copy(idat, 8);
    idat.writeUInt32BE(
      zlib.crc32(Buffer.concat([Buffer.from('IDAT'), compressed])),
      compressed.length + 8
    );

    const iend = Buffer.from([
      0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ]);

    return Buffer.concat([signature, ihdr, idat, iend]);
  }

  console.log('📄 Copying static assets...');

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
