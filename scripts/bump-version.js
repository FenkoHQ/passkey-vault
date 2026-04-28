#!/usr/bin/env node
// Syncs package.json, package-lock.json, and both source manifests to a given version.
// Usage:
//   node scripts/bump-version.js 0.5.0
//   node scripts/bump-version.js v0.5.0
//   node scripts/bump-version.js          (reads latest git tag)

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const root = path.join(__dirname, '..');

function getLatestTag() {
  try {
    const tag = execSync('git describe --tags --abbrev=0', { encoding: 'utf8' }).trim();
    return tag.startsWith('v') ? tag.slice(1) : tag;
  } catch {
    console.error('No git tags found. Pass a version as an argument: node scripts/bump-version.js 1.2.3');
    process.exit(1);
  }
}

function validateVersion(v) {
  if (!/^\d+\.\d+\.\d+$/.test(v)) {
    console.error(`Invalid version "${v}". Must be x.y.z`);
    process.exit(1);
  }
}

function bumpFile(filePath, version) {
  const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const old = content.version;
  content.version = version;
  fs.writeFileSync(filePath, JSON.stringify(content, null, 2) + '\n');
  console.log(`  ${path.relative(root, filePath)}: ${old} -> ${version}`);
}

function bumpPackageLock(filePath, version) {
  const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const old = content.version;
  content.version = version;
  if (content.packages?.['']) {
    content.packages[''].version = version;
  }
  fs.writeFileSync(filePath, JSON.stringify(content, null, 2) + '\n');
  console.log(`  ${path.relative(root, filePath)}: ${old} -> ${version}`);
}

const arg = process.argv[2];
const version = arg ? (arg.startsWith('v') ? arg.slice(1) : arg) : getLatestTag();
validateVersion(version);

console.log(`Bumping to ${version}...`);
bumpFile(path.join(root, 'package.json'), version);
bumpPackageLock(path.join(root, 'package-lock.json'), version);
bumpFile(path.join(root, 'src/manifest.json'), version);
bumpFile(path.join(root, 'src/manifest.firefox.json'), version);
console.log('Done.');
