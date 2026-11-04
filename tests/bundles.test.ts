/**
 * The content script and the page shim are loaded into every page the user
 * opens, so they must not carry the Public Suffix List (about 90 KB): the
 * background answers RP ID questions for them.
 */

import { spawnSync } from 'child_process';

// esbuild refuses to run inside jsdom (its TextEncoder check fails there), so
// the bundle is resolved in a child process.
function inputsOf(entryPoint: string): string[] {
  const script = `
    require('esbuild')
      .build({
        entryPoints: [${JSON.stringify(entryPoint)}],
        bundle: true,
        write: false,
        metafile: true,
        format: 'iife',
        platform: 'browser',
        logLevel: 'silent',
      })
      .then((result) => console.log(JSON.stringify(Object.keys(result.metafile.inputs))));
  `;
  const run = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8' });
  if (run.status !== 0) throw new Error(run.stderr);
  return JSON.parse(run.stdout);
}

describe('bundles loaded into every page', () => {
  it.each(['src/content/content.ts', 'src/content/webauthn-inject.ts'])(
    '%s does not include the Public Suffix List',
    (entryPoint) => {
      const inputs = inputsOf(entryPoint);
      expect(inputs).toContain(entryPoint);
      expect(inputs).not.toContain('src/utils/public-suffix-list.ts');
      expect(inputs).not.toContain('src/utils/domain.ts');
    }
  );

  it('the background does include it', () => {
    expect(inputsOf('src/background/background.ts')).toContain('src/utils/public-suffix-list.ts');
  });
});
