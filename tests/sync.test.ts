import { execFileSync } from 'child_process';
import { resolve } from 'path';

test('browser and mobile sync regressions', () => {
  const output = execFileSync(process.execPath, [resolve('tests/sync/regression.test.cjs')], {
    encoding: 'utf8',
    timeout: 30000,
  });
  expect(output).toContain('# fail 0');
}, 35000);
