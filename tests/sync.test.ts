import { execFileSync } from 'child_process';
import { resolve } from 'path';

test('browser and mobile sync regressions', () => {
  // execFileSync throws on test failure, independent of the reporter's format.
  execFileSync(process.execPath, [resolve('tests/sync/regression.test.cjs')], {
    encoding: 'utf8',
    timeout: 30000,
  });
}, 35000);
