/**
 * Real Chromium for WebAuthn end-to-end tests.
 *
 * Pages are served over HTTPS for made-up sites (https://shop.test,
 * https://login.bank.test, ...) so ceremonies run on realistic origins:
 * subdomains, parent-domain RP IDs, cross-site iframes. Chrome maps every
 * *.test host to a local server and trusts its throwaway certificate by
 * public-key hash (--ignore-certificate-errors-spki-list, the switch
 * web-platform-tests use), so the pages are genuinely secure contexts and
 * WebAuthn runs as it would on the web, with no certificate error.
 *
 * Two browsers: one with the built extension (dist/), and one without it
 * whose page gets a CDP virtual authenticator. The second is Chrome's own
 * WebAuthn client: what the vault must match.
 */

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as https from 'https';
import * as os from 'os';
import * as path from 'path';
import type { AddressInfo } from 'net';
import { chromium, type BrowserContext, type Page } from 'playwright';

export const DIST = path.resolve(__dirname, '../../dist');

export interface Site {
  /** Extra routes: path -> handler returning [status, contentType, body]. */
  routes: Map<string, (host: string) => [number, string, string]>;
  port: number;
  spkiHash: string;
  close(): Promise<void>;
}

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>test page</title></head>
<body><h1>ceremony page</h1><div id="frames"></div></body></html>`;

/** A self-signed certificate for *.test, made with openssl for this run only. */
function certificate(dir: string): { key: string; cert: string; spkiHash: string } {
  const key = path.join(dir, 'key.pem');
  const cert = path.join(dir, 'cert.pem');
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:prime256v1',
      '-nodes',
      '-keyout',
      key,
      '-out',
      cert,
      '-days',
      '2',
      '-subj',
      '/CN=fenko-vault-e2e',
      '-addext',
      'subjectAltName=DNS:*.test,DNS:test,DNS:*.bank.test,DNS:*.shop.test,DNS:*.example.test,DNS:*.co.test',
    ],
    { stdio: 'ignore' }
  );
  const spki = execFileSync('openssl', ['x509', '-in', cert, '-pubkey', '-noout']);
  const der = execFileSync('openssl', ['pkey', '-pubin', '-outform', 'der'], { input: spki });
  const spkiHash = require('crypto').createHash('sha256').update(der).digest('base64');
  return { key: fs.readFileSync(key, 'utf8'), cert: fs.readFileSync(cert, 'utf8'), spkiHash };
}

export async function startSite(): Promise<Site> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fenko-vault-site-'));
  const { key, cert, spkiHash } = certificate(dir);
  const routes: Site['routes'] = new Map();
  const server = https.createServer({ key, cert }, (request, response) => {
    const host = (request.headers.host || '').replace(/:\d+$/, '');
    const url = new URL(request.url || '/', `https://${host}`);
    const route = routes.get(url.pathname);
    const [status, type, body] = route ? route(host) : [200, 'text/html; charset=utf-8', PAGE];
    response.writeHead(status, {
      'content-type': type,
      // Let tests frame any test site inside any other.
      'content-security-policy': 'frame-ancestors *',
    });
    response.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    routes,
    port,
    spkiHash,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
        fs.rmSync(dir, { recursive: true, force: true });
      }),
  };
}

function chromeArgs(site: Site): string[] {
  return [
    // Every *.test host on any port reaches the local server.
    `--host-resolver-rules=MAP *.test 127.0.0.1:${site.port}, MAP test 127.0.0.1:${site.port}`,
    `--ignore-certificate-errors-spki-list=${site.spkiHash}`,
  ];
}

export async function launchWithVault(
  site: Site
): Promise<{ context: BrowserContext; extensionId: string }> {
  if (!fs.existsSync(path.join(DIST, 'manifest.json'))) {
    throw new Error('Build the extension first: npm run build:chrome');
  }
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fenko-vault-e2e-'));
  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium',
    headless: true,
    args: [...chromeArgs(site), `--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`],
  });
  const worker = context.serviceWorkers()[0] || (await context.waitForEvent('serviceworker'));
  return { context, extensionId: new URL(worker.url()).host };
}

export async function launchNative(site: Site): Promise<BrowserContext> {
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fenko-native-e2e-'));
  return chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium',
    headless: true,
    args: chromeArgs(site),
  });
}

/** Give a page a platform authenticator that always succeeds, as Chrome's own WebAuthn client sees one. */
export async function addVirtualAuthenticator(page: Page): Promise<string> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
    },
  });
  return authenticatorId;
}
