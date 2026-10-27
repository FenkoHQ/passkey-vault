import { spawnSync } from 'child_process';
import { readdirSync, readFileSync } from 'fs';

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

// ---------------------------------------------------------------------------
// What the publishing jobs may run, and with which credentials.

const WORKFLOWS = readdirSync('.github/workflows')
  .filter((name) => name.endsWith('.yml'))
  .map((name) => ({ name, text: readFileSync(`.github/workflows/${name}`, 'utf8') }));

/** The body of each job under `jobs:`, keyed by job id. */
function jobsOf(text: string): Record<string, string> {
  const body = text.split(/^jobs:\n/m)[1] ?? '';
  const jobs: Record<string, string> = {};
  for (const chunk of body.split(/^(?=  [\w-]+:\s*$)/m)) {
    const id = /^ {2}([\w-]+):/.exec(chunk)?.[1];
    if (id) jobs[id] = chunk;
  }
  return jobs;
}

/** Every `run:` script in a workflow, as written (expressions unexpanded). */
function runScripts(text: string): string[] {
  const lines = text.split('\n');
  const scripts: string[] = [];
  lines.forEach((line, index) => {
    const match = /^(\s*)(?:- )?run:\s*(.*)$/.exec(line);
    if (!match) return;
    const indent = match[1].length;
    const script = [match[2]];
    for (let next = index + 1; next < lines.length; next++) {
      const body = lines[next];
      if (body.trim() !== '' && body.search(/\S/) <= indent) break;
      script.push(body);
    }
    scripts.push(script.join('\n'));
  });
  return scripts;
}

const release = jobsOf(workflow);
const PUBLISHING_JOBS = ['publish-chrome', 'publish-firefox', 'publish-play', 'release'];

test.each(PUBLISHING_JOBS)('%s runs in the reviewable release environment', (job) => {
  expect(release[job]).toMatch(/^ {4}environment: release$/m);
});

test('the TestFlight upload runs in the release environment too', () => {
  const testflight = WORKFLOWS.find((w) => w.name === 'ios-testflight.yml')!;
  expect(jobsOf(testflight.text).build).toMatch(/^ {4}environment: release$/m);
});

test('no release script has a secret expanded into its text', () => {
  for (const script of runScripts(workflow)) {
    expect(script).not.toMatch(/\$\{\{\s*(secrets\.|steps\.token\.)/);
  }
});

test('AMO credentials reach web-ext through its environment variables', () => {
  const job = release['publish-firefox'];
  expect(job).toMatch(/WEB_EXT_API_KEY: \$\{\{ secrets\.AMO_JWT_ISSUER \}\}/);
  expect(job).toMatch(/WEB_EXT_API_SECRET: \$\{\{ secrets\.AMO_JWT_SECRET \}\}/);
  expect(job).not.toMatch(/--api-(key|secret)/);
});

test('web-ext runs from the lockfile-installed node_modules', () => {
  const job = release['publish-firefox'];
  expect(job).toMatch(/npm ci --ignore-scripts/);
  expect(job).toMatch(/\.\/node_modules\/\.bin\/web-ext sign/);

  const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
  const lock = JSON.parse(readFileSync('package-lock.json', 'utf8'));
  expect(pkg.devDependencies['web-ext']).toMatch(/^\d+\.\d+\.\d+$/);
  expect(lock.packages['node_modules/web-ext'].version).toBe(pkg.devDependencies['web-ext']);
});

test.each(WORKFLOWS.map((w) => [w.name, w.text]))(
  '%s fetches no unpinned tool with npx',
  (_name, text) => {
    for (const script of runScripts(text)) {
      expect(script).not.toMatch(/\bnpx\s+(--yes|-y)\b/);
      expect(script).not.toMatch(/\bnpx\s+[\w@/.-]+@/);
    }
  }
);

test.each(WORKFLOWS.map((w) => [w.name, w.text]))(
  '%s pins every action to a commit',
  (_name, text) => {
    const uses = [...text.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1]);
    for (const action of uses) {
      expect(action).toMatch(/@[0-9a-f]{40}$/);
    }
  }
);
