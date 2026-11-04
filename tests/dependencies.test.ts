/**
 * Every runtime dependency must be used by something that ships: the
 * extension, the shared mobile web app, or a build script that copies a file
 * out of node_modules. An unused one still runs its install scripts on every
 * `npm ci` and sits in the supply chain for nothing.
 */

import { readdirSync, readFileSync, statSync } from 'fs';
import { join } from 'path';

const ROOT = join(__dirname, '..');
const SOURCES = ['src', 'android/web/src', 'android', 'ios', 'scripts', 'build-extension.js'];
const EXTENSIONS = /\.(ts|js|cjs|mjs|sh)$/;
const SKIP = new Set(['node_modules', 'build', 'dist', '.gradle', 'web']);

function files(path: string): string[] {
  const full = join(ROOT, path);
  if (!statSync(full, { throwIfNoEntry: false })) return [];
  if (statSync(full).isFile()) return [full];
  return readdirSync(full, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory()) {
      return SKIP.has(entry.name) ? [] : files(join(path, entry.name));
    }
    return EXTENSIONS.test(entry.name) ? [join(full, entry.name)] : [];
  });
}

const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/** An import or require of the package (or a subpath), or a path into its folder. */
function usedBy(name: string, source: string): boolean {
  const pkg = escape(name);
  return new RegExp(
    `(from\\s+|require\\(|import\\()['"]${pkg}(/[^'"]*)?['"]|node_modules/${pkg}/`
  ).test(source);
}

describe('runtime dependencies', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const sources = [...new Set(SOURCES.flatMap(files))].map((file) => readFileSync(file, 'utf8'));

  it.each(Object.keys(pkg.dependencies || {}))('%s is used by shipped code', (name) => {
    expect(sources.some((source) => usedBy(name, source))).toBe(true);
  });
});
