#!/usr/bin/env node
/**
 * Automated screenshot and video capture for PassKey Vault extension.
 *
 * Usage:
 *   npm run capture          — screenshots + video
 *   npm run capture:screenshots
 *   npm run capture:video
 *
 * Requires: built extension in dist/  (run `npm run build:chrome` first)
 * Requires: display (Wayland/X11). On headless CI use: xvfb-run node scripts/capture-assets.js
 */

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const ROOT = path.join(__dirname, '..');
const EXTENSION_PATH = path.join(ROOT, 'dist');
const SCREENSHOTS_DIR = path.join(ROOT, 'docs', 'screenshots');
const CWS_DIR = path.join(ROOT, 'docs', 'cws');
const VIDEO_DIR = path.join(ROOT, 'docs', 'video');
const PROFILE_DIR = path.join(ROOT, '.playwright-profile');

// CWS requirement: 1280×800, full bleed, max 5
const CWS_W = 1280;
const CWS_H = 800;
const CWS_BG = '#0d0d0d'; // dark canvas — makes black/yellow UI pop

// Popup is 360×400 per CSS; add some breathing room for the page chrome
const POPUP_W = 400;
const POPUP_H = 520;

const MOCK_PASSKEYS = [
  {
    id: 'cred_github_01abcdef0123456789',
    rpId: 'github.com',
    origin: 'https://github.com',
    user: { id: 'u1', name: 'jane@example.com', displayName: 'Jane' },
    publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE',
    createdAt: Date.now() - 1000 * 60 * 60 * 24 * 5,
    counter: 12,
    lastUsed: Date.now() - 1000 * 60 * 60 * 2,
  },
  {
    id: 'cred_google_02abcdef0123456789',
    rpId: 'accounts.google.com',
    origin: 'https://accounts.google.com',
    user: { id: 'u2', name: 'jane@example.com', displayName: 'Jane' },
    publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAF',
    createdAt: Date.now() - 1000 * 60 * 60 * 24 * 3,
    counter: 7,
    lastUsed: Date.now() - 1000 * 60 * 30,
  },
  {
    id: 'cred_notion_03abcdef0123456789',
    rpId: 'notion.so',
    origin: 'https://notion.so',
    user: { id: 'u3', name: 'jdoe', displayName: 'John' },
    publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAG',
    createdAt: Date.now() - 1000 * 60 * 60 * 24,
    counter: 3,
    lastUsed: Date.now() - 1000 * 60 * 10,
  },
  {
    id: 'cred_cloudflare_04abcdef012345678',
    rpId: 'cloudflare.com',
    origin: 'https://cloudflare.com',
    user: { id: 'u4', name: 'john@example.com', displayName: 'John' },
    publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAH',
    createdAt: Date.now() - 1000 * 60 * 60 * 12,
    counter: 1,
    lastUsed: Date.now() - 1000 * 60 * 5,
  },
];

const MODE = process.argv[2] || 'all';

async function launchWithExtension(opts = {}) {
  const dir = opts.profileDir || PROFILE_DIR;
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });

  return chromium.launchPersistentContext(dir, {
    headless: false,
    args: [
      `--disable-extensions-except=${EXTENSION_PATH}`,
      `--load-extension=${EXTENSION_PATH}`,
      '--no-first-run',
      '--no-default-browser-check',
    ],
    viewport: { width: POPUP_W, height: POPUP_H },
    ...opts.contextOpts,
  });
}

async function getExtensionId(ctx) {
  let sw = ctx.serviceWorkers()[0];
  if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 10000 });
  const id = sw.url().split('/')[2];
  console.log(`  Extension ID: ${id}`);
  return id;
}

async function extPage(ctx, extensionId, file) {
  const page = await ctx.newPage();
  await page.goto(`chrome-extension://${extensionId}/${file}`);
  return page;
}

// Screenshot the .container element directly — no dead space, no viewport clipping.
async function shotElement(page, name) {
  const file = path.join(SCREENSHOTS_DIR, name);
  const el = page.locator('.container').first();
  await el.screenshot({ path: file });
  console.log(`  ✅ ${name}`);
}

async function injectPasskeys(page, passkeys) {
  await page.evaluate((data) => {
    return new Promise((resolve) =>
      chrome.storage.local.set(
        { passkeys: data, master_password_setup_skipped: true },
        resolve
      )
    );
  }, passkeys);
}

async function waitReady(page, ms = 600) {
  await page.waitForLoadState('domcontentloaded');
  await page.waitForTimeout(ms);
}

// ─── Screenshots ─────────────────────────────────────────────────────────────

async function captureScreenshots() {
  console.log('\n📸 Capturing screenshots...');
  fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });

  const ctx = await launchWithExtension();
  const id = await getExtensionId(ctx);

  // 01 — popup empty state
  {
    const p = await extPage(ctx, id, 'popup.html');
    await injectPasskeys(p, []);
    await p.reload();
    await waitReady(p);
    await shotElement(p, '01-popup-empty.png');
    await p.close();
  }

  // 02 — popup with passkeys (list view)
  {
    const p = await extPage(ctx, id, 'popup.html');
    await injectPasskeys(p, MOCK_PASSKEYS);
    await p.reload();
    await waitReady(p);
    await shotElement(p, '02-popup-list.png');

    // 03 — search active
    await p.fill('#search-input', 'github');
    await p.waitForTimeout(300);
    await shotElement(p, '03-popup-search.png');

    // 04 — expanded passkey detail
    await p.fill('#search-input', '');
    await p.waitForTimeout(200);
    const expandBtn = p.locator('.passkey-item .expand-btn').first();
    if (await expandBtn.count()) {
      await expandBtn.click();
      await p.waitForTimeout(300);
    }
    await shotElement(p, '04-popup-detail.png');

    await p.close();
  }

  // 05 — import screen
  {
    const p = await extPage(ctx, id, 'import.html');
    await waitReady(p, 800);
    await shotElement(p, '05-import.png');
    await p.close();
  }

  // 06 — sync setup (create mode)
  {
    const p = await extPage(ctx, id, 'sync-setup.html');
    await waitReady(p, 800);
    await shotElement(p, '06-sync-setup-create.png');

    // 07 — join mode
    const joinBtn = p.locator('button', { hasText: /join/i }).first();
    if (await joinBtn.count()) {
      await joinBtn.click();
      await p.waitForTimeout(300);
      await shotElement(p, '07-sync-setup-join.png');
    }
    await p.close();
  }

  // 08 — sync settings (not configured)
  {
    const p = await extPage(ctx, id, 'sync-settings.html');
    await waitReady(p, 800);
    await shotElement(p, '08-sync-settings-empty.png');
    await p.close();
  }

  // 09 — options page (interception)
  {
    const p = await extPage(ctx, id, 'options.html');
    await waitReady(p, 800);
    await p.screenshot({ path: path.join(SCREENSHOTS_DIR, '09-options-interception.png') });
    console.log('  \u2705 09-options-interception.png');

    // 10 — options developer tab
    const devBtn = p.locator('.nav-item', { hasText: /developer/i }).first();
    if (await devBtn.count()) {
      await devBtn.click();
      await p.waitForTimeout(300);
      await p.screenshot({ path: path.join(SCREENSHOTS_DIR, '10-options-developer.png') });
      console.log('  \u2705 10-options-developer.png');
    }
    await p.close();
  }

  // 11 — emergency access login
  {
    const p = await extPage(ctx, id, 'emergency.html');
    await waitReady(p, 800);
    await shotElement(p, '11-emergency-login.png');
    await p.close();
  }

  await ctx.close();
  console.log(`\n  Saved to ${SCREENSHOTS_DIR}`);
}

// ─── Video ───────────────────────────────────────────────────────────────────

async function captureVideo() {
  console.log('\n🎬 Recording demo video...');
  fs.mkdirSync(VIDEO_DIR, { recursive: true });

  const ctx = await launchWithExtension({
    profileDir: path.join(ROOT, '.playwright-profile-video'),
    contextOpts: {
      recordVideo: {
        dir: VIDEO_DIR,
        size: { width: POPUP_W, height: POPUP_H },
      },
    },
  });
  const id = await getExtensionId(ctx);

  const p = await extPage(ctx, id, 'popup.html');
  await p.setViewportSize({ width: POPUP_W, height: POPUP_H });
  await injectPasskeys(p, MOCK_PASSKEYS);
  await p.reload();
  await waitReady(p, 800);

  // Walk through the UI
  await p.waitForTimeout(1000);

  // Search demo
  await p.fill('#search-input', 'git');
  await p.waitForTimeout(800);
  await p.fill('#search-input', '');
  await p.waitForTimeout(500);

  // Expand first passkey
  const expandBtn = p.locator('.passkey-item .expand-btn').first();
  if (await expandBtn.count()) {
    await expandBtn.click();
    await p.waitForTimeout(1000);
    await expandBtn.click();
    await p.waitForTimeout(500);
  }

  // Scroll through list
  await p.evaluate(() => {
    document.getElementById('passkey-list')?.scrollTo({ top: 200, behavior: 'smooth' });
  });
  await p.waitForTimeout(800);
  await p.evaluate(() => {
    document.getElementById('passkey-list')?.scrollTo({ top: 0, behavior: 'smooth' });
  });
  await p.waitForTimeout(600);

  // Open import page briefly
  const importBtn = p.locator('#import-btn');
  if (await importBtn.count()) {
    await importBtn.click();
    await p.waitForTimeout(1200);
  }

  await p.waitForTimeout(800);

  const videoPath = await p.video()?.path();
  await ctx.close();

  // Rename from random hash to deterministic name
  if (videoPath && fs.existsSync(videoPath)) {
    const dest = path.join(VIDEO_DIR, 'demo.webm');
    fs.renameSync(videoPath, dest);
    console.log(`  ✅ Saved to ${dest}`);
  }
}

// ─── CWS Screenshots (1280×800 full bleed) ───────────────────────────────────

async function captureCWS() {
  console.log('\n🏪 Capturing CWS screenshots (1280×800)...');
  fs.mkdirSync(CWS_DIR, { recursive: true });

  const ctx = await launchWithExtension({
    profileDir: path.join(ROOT, '.playwright-profile-cws'),
    contextOpts: { viewport: { width: CWS_W, height: CWS_H } },
  });
  const id = await getExtensionId(ctx);

  // Inject passkeys once via a throwaway page so storage is set for all pages
  const setup = await extPage(ctx, id, 'popup.html');
  await injectPasskeys(setup, MOCK_PASSKEYS);
  await setup.close();

  // Scales container to fill ~90% of CWS_H, centered on CWS_BG canvas.
  // zoom: 1 means no scaling — we calculate it from the actual element height.
  // tagline shown in the reserved text strip at the bottom of each CWS image
  const TAGLINES = {
    'cws-01-vault.png':    'YOUR PASSKEYS. YOUR DEVICE. NOBODY ELSE.',
    'cws-02-search.png':   'FIND ANY PASSKEY INSTANTLY.',
    'cws-03-detail.png':   'FULL CONTROL OVER EVERY CREDENTIAL.',
    'cws-04-settings.png': 'DEVELOPER TOOLS BUILT RIGHT IN.',
    'cws-05-sync.png':     'SYNC ACROSS DEVICES. NO CLOUD REQUIRED.',
  };

  const cwsShot = async (page, name) => {
    await page.setViewportSize({ width: CWS_W, height: CWS_H });
    await page.waitForTimeout(200);

    // Measure the container's visible (non-scrollable) height
    const containerHeight = await page.evaluate(() => {
      const el = document.querySelector('.container');
      if (!el) return 400;
      const rect = el.getBoundingClientRect();
      return Math.min(rect.height, window.innerHeight * 0.85);
    });

    // Reserve 110px at the bottom for the tagline strip
    const usableH = CWS_H - 110;
    const targetH = usableH * 0.88;
    const zoom = Math.min(targetH / containerHeight, 2.4);
    const tagline = TAGLINES[name] || '';

    await page.addStyleTag({
      content: `
        html, body {
          width: ${CWS_W}px !important;
          height: ${CWS_H}px !important;
          min-height: ${CWS_H}px !important;
          background: linear-gradient(160deg, #0a0a0a 0%, #111008 60%, #1a1200 100%) !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          overflow: hidden !important;
          margin: 0 !important;
          padding: 0 0 110px 0 !important;
          position: relative !important;
        }
        /* dot-grid texture */
        body::before {
          content: '' !important;
          position: fixed !important;
          inset: 0 !important;
          background-image: radial-gradient(circle, rgba(252,211,77,0.08) 1px, transparent 1px) !important;
          background-size: 28px 28px !important;
          pointer-events: none !important;
          z-index: 0 !important;
        }
        /* yellow corner accents */
        body::after {
          content: '' !important;
          position: fixed !important;
          top: 0 !important; left: 0 !important;
          width: 120px !important; height: 4px !important;
          background: #fcd34d !important;
          z-index: 2 !important;
        }
        .container {
          zoom: ${zoom.toFixed(3)} !important;
          box-shadow:
            0 32px 120px rgba(0,0,0,0.85),
            0 0 0 1px rgba(252,211,77,0.15),
            0 0 60px rgba(252,211,77,0.06) !important;
          position: relative !important;
          z-index: 1 !important;
        }
      `,
    });

    // Inject tagline strip + right-side accent line
    await page.evaluate(({ text, w, h }) => {
      // bottom strip
      const strip = document.createElement('div');
      strip.style.cssText = `
        position: fixed; bottom: 0; left: 0; right: 0; height: 110px;
        background: #fcd34d;
        display: flex; align-items: center; justify-content: space-between;
        padding: 0 56px;
        z-index: 10;
        border-top: 3px solid #000;
      `;
      strip.innerHTML = `
        <span style="font-family:'Courier New',monospace;font-size:18px;font-weight:700;
          text-transform:uppercase;letter-spacing:2px;color:#000;max-width:700px">
          ${text}
        </span>
        <span style="font-family:'Courier New',monospace;font-size:13px;font-weight:700;
          text-transform:uppercase;letter-spacing:1px;color:#000;opacity:0.5">
          PASSKEY VAULT
        </span>
      `;
      document.body.appendChild(strip);

      // right-side yellow accent bar
      const bar = document.createElement('div');
      bar.style.cssText = `
        position: fixed; top: 0; right: 0; width: 4px; height: 100%;
        background: linear-gradient(to bottom, #fcd34d, transparent);
        z-index: 10;
      `;
      document.body.appendChild(bar);
    }, { text: tagline, w: CWS_W, h: CWS_H });

    await page.waitForTimeout(150);
    const file = path.join(CWS_DIR, name);
    await page.screenshot({ path: file, clip: { x: 0, y: 0, width: CWS_W, height: CWS_H } });
    console.log(`  ✅ ${name}  (zoom: ${zoom.toFixed(2)}×)`);
    await page.close();
  };

  // 1 — vault with passkeys
  {
    const p = await extPage(ctx, id, 'popup.html');
    await waitReady(p);
    await cwsShot(p, 'cws-01-vault.png');
  }

  // 2 — search
  {
    const p = await extPage(ctx, id, 'popup.html');
    await waitReady(p);
    await p.fill('#search-input', 'github');
    await p.waitForTimeout(300);
    await cwsShot(p, 'cws-02-search.png');
  }

  // 3 — expanded passkey detail
  {
    const p = await extPage(ctx, id, 'popup.html');
    await waitReady(p);
    const btn = p.locator('.expand-btn').first();
    if (await btn.count()) {
      await btn.click();
      await p.waitForTimeout(300);
    }
    await cwsShot(p, 'cws-03-detail.png');
  }

  // 4 — settings / developer tools
  {
    const p = await extPage(ctx, id, 'options.html');
    await waitReady(p, 800);
    // Click Developer tab
    const devBtn = p.locator('.nav-item', { hasText: /developer/i }).first();
    if (await devBtn.count()) {
      await devBtn.click();
      await p.waitForTimeout(300);
    }
    // Options page is full-tab, screenshot viewport directly
    await p.setViewportSize({ width: CWS_W, height: CWS_H });
    await p.waitForTimeout(200);

    // Inject tagline strip
    const tagline = TAGLINES['cws-04-settings.png'] || '';
    await p.evaluate(({ text }) => {
      const strip = document.createElement('div');
      strip.style.cssText = `
        position: fixed; bottom: 0; left: 0; right: 0; height: 80px;
        background: #fcd34d;
        display: flex; align-items: center; justify-content: space-between;
        padding: 0 56px; z-index: 10000;
        border-top: 3px solid #000;
      `;
      strip.innerHTML = `
        <span style="font-family:'Courier New',monospace;font-size:18px;font-weight:700;
          text-transform:uppercase;letter-spacing:2px;color:#000;max-width:700px">${text}</span>
        <span style="font-family:'Courier New',monospace;font-size:13px;font-weight:700;
          text-transform:uppercase;letter-spacing:1px;color:#000;opacity:0.5">PASSKEY VAULT</span>
      `;
      document.body.appendChild(strip);
    }, { text: tagline });

    await p.waitForTimeout(150);
    const file = path.join(CWS_DIR, 'cws-04-settings.png');
    await p.screenshot({ path: file, clip: { x: 0, y: 0, width: CWS_W, height: CWS_H } });
    console.log(`  \u2705 cws-04-settings.png`);
    await p.close();
  }

  // 5 — sync setup
  {
    const p = await extPage(ctx, id, 'sync-setup.html');
    await waitReady(p, 800);
    await cwsShot(p, 'cws-05-sync.png');
  }

  await ctx.close();
  console.log(`\n  Saved to ${CWS_DIR}`);
}

// ─── Promo Tiles ─────────────────────────────────────────────────────────────
// Small:   440×280  (sidebar / small promo tile)
// Marquee: 1400×560 (marquee banner)

async function capturePromoTiles() {
  console.log('\n🎨 Capturing promo tiles...');
  fs.mkdirSync(CWS_DIR, { recursive: true });

  // Small tile uses a plain page — UI panel doesn't fit at 440px wide
  // Marquee loads the real popup and overlays left-side typography
  const ctx = await launchWithExtension({
    profileDir: path.join(ROOT, '.playwright-profile-cws'),
    contextOpts: { viewport: { width: 1400, height: 560 } },
  });
  const id = await getExtensionId(ctx);

  const setup = await extPage(ctx, id, 'popup.html');
  await injectPasskeys(setup, MOCK_PASSKEYS);
  await setup.close();

  // ── Small promo 440×280 ───────────────────────────────────────────────────
  {
    const p = await ctx.newPage();
    await p.setViewportSize({ width: 440, height: 280 });
    await p.setContent(`<!DOCTYPE html>
<html><head><style>
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body {
  width: 440px; height: 280px; overflow: hidden;
  background: linear-gradient(160deg, #0a0a0a 0%, #111008 60%, #1a1200 100%);
  font-family: 'Courier New', Courier, monospace;
  position: relative;
}
body::before {
  content: ''; position: absolute; inset: 0;
  background-image: radial-gradient(circle, rgba(252,211,77,0.08) 1px, transparent 1px);
  background-size: 28px 28px; pointer-events: none;
}
.top-bar   { position: absolute; top: 0; left: 0; width: 80px; height: 4px; background: #fcd34d; }
.right-bar { position: absolute; top: 0; right: 0; width: 4px; height: 100%; background: linear-gradient(to bottom, #fcd34d, transparent); }
.bottom-bar { position: absolute; bottom: 0; left: 0; right: 0; height: 3px; background: #fcd34d; }
.content {
  position: absolute; inset: 0;
  display: flex; flex-direction: column;
  align-items: flex-start; justify-content: center;
  padding: 28px 36px; gap: 10px;
}
.icon-wrap {
  width: 40px; height: 40px;
  border: 3px solid #fcd34d;
  display: flex; align-items: center; justify-content: center;
  margin-bottom: 6px;
}
.brand { font-size: 20px; font-weight: 700; color: #fff; text-transform: uppercase; letter-spacing: 2px; }
.tagline { font-size: 11px; font-weight: 700; color: #fcd34d; text-transform: uppercase; letter-spacing: 1.5px; line-height: 1.7; }
</style></head>
<body>
  <div class="top-bar"></div>
  <div class="right-bar"></div>
  <div class="bottom-bar"></div>
  <div class="content">
    <div class="icon-wrap">
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24"
        fill="none" stroke="#fcd34d" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
    </div>
    <div class="brand">Passkey Vault</div>
    <div class="tagline">Your passkeys.<br>Your device.<br>Nobody else.</div>
  </div>
</body></html>`);
    await p.waitForTimeout(300);
    const file = path.join(CWS_DIR, 'promo-small.png');
    await p.screenshot({ path: file, clip: { x: 0, y: 0, width: 440, height: 280 } });
    console.log(`  ✅ promo-small.png  (440×280)`);
    await p.close();
  }

  // ── Marquee promo 1400×560 ────────────────────────────────────────────────
  {
    const p = await extPage(ctx, id, 'popup.html');
    await p.setViewportSize({ width: 1400, height: 560 });
    await waitReady(p);

    await p.addStyleTag({
      content: `
        html, body {
          width: 1400px !important; height: 560px !important;
          min-height: 560px !important;
          background: linear-gradient(160deg, #0a0a0a 0%, #111008 60%, #1a1200 100%) !important;
          display: flex !important;
          align-items: center !important;
          justify-content: flex-end !important;
          overflow: hidden !important;
          margin: 0 !important; padding: 0 !important;
          position: relative !important;
        }
        body::before {
          content: '' !important; position: fixed !important; inset: 0 !important;
          background-image: radial-gradient(circle, rgba(252,211,77,0.08) 1px, transparent 1px) !important;
          background-size: 28px 28px !important;
          pointer-events: none !important; z-index: 0 !important;
        }
        .container {
          zoom: 1.15 !important;
          position: relative !important; z-index: 1 !important;
          margin-right: 100px !important;
          box-shadow:
            0 32px 120px rgba(0,0,0,0.85),
            0 0 0 1px rgba(252,211,77,0.15),
            0 0 60px rgba(252,211,77,0.06) !important;
        }
      `,
    });

    await p.evaluate(() => {
      const topBar = document.createElement('div');
      topBar.style.cssText = 'position:fixed;top:0;left:0;width:120px;height:4px;background:#fcd34d;z-index:10';
      document.body.appendChild(topBar);

      const rightBar = document.createElement('div');
      rightBar.style.cssText = 'position:fixed;top:0;right:0;width:4px;height:100%;background:linear-gradient(to bottom,#fcd34d,transparent);z-index:10';
      document.body.appendChild(rightBar);

      const divider = document.createElement('div');
      divider.style.cssText = 'position:fixed;left:660px;top:8%;height:84%;width:1px;background:rgba(252,211,77,0.12);z-index:5';
      document.body.appendChild(divider);

      const text = document.createElement('div');
      text.style.cssText = `
        position:fixed; left:80px; top:50%; transform:translateY(-50%);
        z-index:10; font-family:'Courier New',Courier,monospace;
      `;
      text.innerHTML = `
        <div style="font-size:11px;font-weight:700;color:#fcd34d;letter-spacing:3px;
          text-transform:uppercase;margin-bottom:22px">Browser Extension</div>
        <div style="font-size:56px;font-weight:700;color:#fff;text-transform:uppercase;
          letter-spacing:-1px;line-height:1.05">Your<br>Passkeys.</div>
        <div style="font-size:56px;font-weight:700;color:#fcd34d;text-transform:uppercase;
          letter-spacing:-1px;line-height:1.05;margin-bottom:28px">Your Device.</div>
        <div style="font-size:13px;font-weight:700;color:#fff;letter-spacing:2px;
          text-transform:uppercase;opacity:0.45">Nobody else.</div>
      `;
      document.body.appendChild(text);
    });

    await p.waitForTimeout(300);
    const file = path.join(CWS_DIR, 'promo-marquee.png');
    await p.screenshot({ path: file, clip: { x: 0, y: 0, width: 1400, height: 560 } });
    console.log(`  ✅ promo-marquee.png  (1400×560)`);
    await p.close();
  }

  await ctx.close();
  console.log(`\n  Saved to ${CWS_DIR}`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  if (!fs.existsSync(EXTENSION_PATH)) {
    console.error('dist/ not found — run: npm run build:chrome');
    process.exit(1);
  }

  if (MODE === 'all' || MODE === 'screenshots') await captureScreenshots();
  if (MODE === 'all' || MODE === 'video') await captureVideo();
  if (MODE === 'all' || MODE === 'cws') await captureCWS();
  if (MODE === 'all' || MODE === 'promo') await capturePromoTiles();

  console.log('\nDone.');
}

main().catch((err) => {
  console.error('Capture failed:', err);
  process.exit(1);
});
