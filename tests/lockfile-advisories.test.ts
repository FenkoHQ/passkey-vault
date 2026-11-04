/**
 * The lockfile must not fall back to versions with known advisories that were
 * fixed on purpose (npm audit, 2026-10-27). `npm audit` itself needs the
 * registry; this check runs offline on every test run, so a lockfile
 * regenerated from an old cache, or a dependency bump that re-nests an old
 * copy, fails here.
 *
 * Each entry is the first safe version on each major line the tree uses.
 */

import { readFileSync } from 'fs';

const FIXED: Record<string, Record<number, string>> = {
  // GHSA-p8wg-vrv2-v86f, GHSA-2w6w-674q-4c4q, GHSA-8r5x-fm3f-whwj (critical) and others
  handlebars: { 4: '4.7.10' },
  // GHSA-96hv-2xvq-fx4p, GHSA-58qx-3vcg-4xpx
  ws: { 8: '8.21.0' },
  // GHSA-hmw2-7cc7-3qxx
  'form-data': { 4: '4.0.6' },
  // GHSA-c2c7-rcm5-vvqj, GHSA-3v7f-55p6-f55p
  picomatch: { 2: '2.3.2' },
  // GHSA-3ppc-4f35-3m26, GHSA-7r86-cg39-jmmj, GHSA-23c5-xmqv-rm74
  minimatch: { 3: '3.1.4', 9: '9.0.7' },
  // GHSA-q2hr-2g5m-vwhr and earlier ReDoS fixes
  'brace-expansion': { 1: '1.1.21', 2: '2.1.7' },
  // GHSA-52cp-r559-cp3m, GHSA-5p4m-2wfm-xmqj, GHSA-2883-xcg3-v3hh
  'js-yaml': { 3: '3.15.2' },
  // GHSA-rf6f-7fwh-wjgh, GHSA-25h7-pfq9-p65f
  flatted: { 3: '3.4.2' },
  // GHSA-73wf-gq98-2v4g, GHSA-c83g-rgw3-j3cx
  browserslist: { 4: '4.28.7' },
  // GHSA-2g4f-4pwh-qvx6
  ajv: { 6: '6.14.0' },
  // GHSA-w5vr-8v7q-w6rv
  'baseline-browser-mapping': { 2: '2.11.0' },
  // GHSA-4x5r-pxfx-6jf8
  '@babel/core': { 7: '7.29.1' },
  // GHSA-vpq2-c234-7xj6
  '@tootallnate/once': { 2: '2.0.1' },
};

function parse(version: string): number[] {
  return version
    .split('-')[0]
    .split('.')
    .map((part) => Number.parseInt(part, 10));
}

function atLeast(version: string, minimum: string): boolean {
  const [a, b] = [parse(version), parse(minimum)];
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i];
  }
  return true;
}

const lock = JSON.parse(readFileSync('package-lock.json', 'utf8'));
const locked = Object.entries(lock.packages as Record<string, { version?: string }>);

describe('locked dev tooling', () => {
  it.each(Object.keys(FIXED))('%s is at or above its fixed versions', (name) => {
    const copies = locked
      .filter(([path]) => path === `node_modules/${name}` || path.endsWith(`/node_modules/${name}`))
      .map(([path, entry]) => ({ path, version: entry.version ?? '' }));
    expect(copies.length).toBeGreaterThan(0);
    const vulnerable = copies.filter(({ version }) => {
      const minimum = FIXED[name][parse(version)[0]];
      return minimum !== undefined && !atLeast(version, minimum);
    });
    expect(vulnerable).toEqual([]);
  });
});
