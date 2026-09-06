import { spawnSync } from 'child_process';
import { readFileSync } from 'fs';

// Execute the workflow's response handling without making a store request.
const workflow = readFileSync('.github/workflows/release.yml', 'utf8');
const publish = workflow.split('      - name: Publish to Chrome Web Store\n')[1];
const script = publish.split('          STATUS=')[1].split('\n  publish-firefox:')[0];

function checkResponse(response: string) {
  return spawnSync('bash', ['--noprofile', '--norc', '-e', '-c', `STATUS=${script}`], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH, RESPONSE: response },
  });
}

test.each(['OK', 'ITEM_PENDING_REVIEW'])('accepts Chrome status %s', (status) => {
  const result = checkResponse(JSON.stringify({ status: [status] }));
  expect({ status: result.status, stderr: result.stderr }).toEqual({ status: 0, stderr: '' });
});

test('reports pending review separately from publication', () => {
  const result = checkResponse(JSON.stringify({ status: ['ITEM_PENDING_REVIEW'] }));
  expect(result.stdout).toContain('pending review');
  expect(result.stdout).not.toContain('Published to Chrome Web Store');
});

test.each([
  JSON.stringify({ status: ['NOT_AUTHORIZED'] }),
  JSON.stringify({ status: ['UNKNOWN_STATUS'] }),
  JSON.stringify({ status: [] }),
  JSON.stringify({ error: { code: 403 } }),
  'invalid JSON',
])('rejects failed or malformed Chrome response %s', (response) => {
  expect(checkResponse(response).status).not.toBe(0);
});
