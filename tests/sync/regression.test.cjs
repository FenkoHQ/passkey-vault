const { test, before } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const esbuild = require('esbuild');

let browserCode, mobileCode, backgroundCode;
before(async () => {
  async function bundle(file, suffix, strip) {
    let contents = fs.readFileSync(file, 'utf8');
    if (strip) {
      contents = contents.slice(0, contents.lastIndexOf(strip));
    }
    const result = await esbuild.build({
      stdin: {
        contents: contents + suffix,
        resolveDir: require('node:path').dirname(require('node:path').resolve(file)),
        loader: 'ts',
      },
      bundle: true,
      write: false,
      format: 'iife',
      globalName: 'testExports',
      define: { __APP_VERSION__: '"test"' },
    });
    return result.outputFiles[0].text;
  }
  browserCode = await bundle('src/sync/sync-service.ts', '');
  backgroundCode = await bundle(
    'src/background/background.ts',
    '\nexport { BackgroundService };',
    'new BackgroundService();'
  );
  mobileCode = await bundle(
    'android/web/src/app.ts',
    '\nrender = () => {}; export { AndroidSync, getPasskeys, setPasskeys, getTotpEntries, setTotpEntries, mergeNativeSnapshot, restoreFromBin, getSyncConfig };',
    'void boot().catch'
  );
});

function env(code) {
  const storage = new Map();
  const timers = new Map();
  const context = vm.createContext({
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    ArrayBuffer,
    Buffer,
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    console,
    navigator: { platform: 'Linux', userAgent: 'test', maxTouchPoints: 0 },
    document: { getElementById: () => null, addEventListener() {} },
    localStorage: {
      getItem: (k) => storage.get(k) ?? null,
      setItem: (k, v) => storage.set(k, v),
      removeItem: (k) => storage.delete(k),
    },
    chrome: {
      storage: {
        local: {
          get: async (k) => ({ [k]: storage.get(k) }),
          set: async (o) => Object.entries(o).forEach(([k, v]) => storage.set(k, v)),
        },
      },
    },
    WebSocket: { OPEN: 1, CONNECTING: 0 },
    setTimeout: (fn, delay) => {
      const id = Symbol();
      timers.set(id, { fn, delay });
      return id;
    },
    clearTimeout: (id) => timers.delete(id),
    setInterval: () => 1,
    clearInterval() {},
  });
  context.window = context;
  vm.runInContext(code, context);
  return { context, storage, timers, api: context.testExports };
}
const config = {
  enabled: true,
  chainId: 'ab'.repeat(16),
  seedHash: 'ab'.repeat(32),
  deviceId: 'mobile',
  syncSalt: 'cd'.repeat(32),
};
const passkey = {
  id: 'p',
  createdAt: 1,
  counter: 1,
  privateKey: 'unchanged-key',
  rpId: 'example.com',
};
const totp = { id: 't', createdAt: 1, counter: 1, type: 'hotp', secretB64: 'unchanged-secret' };
async function browser() {
  const e = env(browserCode),
    s = new e.api.SyncService();
  Object.assign(s, { chainId: config.chainId, deviceId: 'browser', log() {} });
  await s.deriveKeys(config.seedHash);
  return { ...e, s };
}

test('existing mobile salt does not prevent browser interoperability', async () => {
  const { s } = await browser();
  const e = env(mobileCode),
    m = new e.api.AndroidSync({ ...config });
  await m.deriveKeys();
  const message = { type: 'update', chainId: config.chainId, payload: {} };
  assert.deepEqual(
    JSON.parse(JSON.stringify(await m.decryptMessage(await s.encryptMessage(message)))),
    message
  );
});

test('browser publishes a TOTP-only vault', async () => {
  const { s } = await browser(),
    sent = [];
  s.isConnected = true;
  s.broadcastMessage = async (msg) => sent.push(msg);
  await s.broadcastPasskeyUpdate([], [totp]);
  assert.equal(sent.length, 1);
});

test('mobile merges counters without replacing credential material', () => {
  const e = env(mobileCode),
    m = new e.api.AndroidSync({ ...config });
  e.api.setPasskeys([passkey]);
  e.api.setTotpEntries([totp]);
  m.mergeVault([{ ...passkey, counter: 9 }], [{ ...totp, counter: 9 }], 'peer');
  assert.equal(e.api.getPasskeys()[0].counter, 9);
  assert.equal(e.api.getPasskeys()[0].privateKey, passkey.privateKey);
  assert.equal(e.api.getTotpEntries()[0].counter, 9);
});

test('deletions survive replay of an older snapshot', () => {
  const e = env(mobileCode),
    m = new e.api.AndroidSync({ ...config });
  e.api.setPasskeys([passkey]);
  m.mergeVault([], [], 'peer', [{ kind: 'passkey', id: 'p', deletedAt: 2 }]);
  m.mergeVault([passkey], [], 'old-peer');
  assert.equal(e.api.getPasskeys().length, 0);
});

test('explicit restore beats an older deletion', () => {
  const e = env(mobileCode),
    m = new e.api.AndroidSync({ ...config });
  m.mergeVault([], [], 'peer', [{ kind: 'passkey', id: 'p', deletedAt: 2 }]);
  m.mergeVault([{ ...passkey, updatedAt: 3 }], [], 'peer');
  assert.equal(e.api.getPasskeys().length, 1);
});

test('rate limited updates are queued rather than discarded', async () => {
  const { s, timers } = await browser(),
    frames = [];
  s.relayConnections = [{ ws: { readyState: 1, send: (frame) => frames.push(frame) } }];
  s.lastBroadcastTime = Date.now();
  await s.broadcastMessage({
    type: 'update',
    deviceId: 'browser',
    payload: {},
    timestamp: Date.now(),
  });
  assert.ok(timers.size > 0, 'must schedule delivery');
});

test('snapshot subscription can recover after more than one hour offline', async () => {
  const { s } = await browser(),
    frames = [];
  s.subscribeToChain({ ws: { send: (frame) => frames.push(JSON.parse(frame)) } });
  assert.ok(
    frames.some((frame) => frame.slice(2).some((filter) => !filter.since)),
    'needs a persistent snapshot filter'
  );
});

test('relay rejection retains the snapshot for retry', async () => {
  const { s } = await browser(),
    frames = [];
  const conn = {
    url: 'test',
    ws: { readyState: 1, send: (frame) => frames.push(JSON.parse(frame)) },
  };
  s.relayConnections = [conn];
  const msg = {
    type: 'update',
    deviceId: 'browser',
    chainId: config.chainId,
    payload: {},
    timestamp: Date.now(),
  };
  await s.broadcastMessage(msg);
  await s.handleWebSocketMessage(
    JSON.stringify(['OK', frames[0][1].id, false, 'rate-limited: retry']),
    conn
  );
  assert.equal(s.pendingMessages.size, 1);
});

test('successful relay acknowledgement clears only the acknowledged snapshot', async () => {
  const { s } = await browser(),
    frames = [];
  const conn = {
    url: 'test',
    ws: { readyState: 1, send: (frame) => frames.push(JSON.parse(frame)) },
  };
  s.relayConnections = [conn];
  await s.broadcastMessage({ type: 'update', payload: {}, timestamp: 1 });
  await s.broadcastMessage({ type: 'update', payload: {}, timestamp: 2 });
  await s.handleWebSocketMessage(JSON.stringify(['OK', frames[0][1].id, true, '']), conn);
  assert.equal(s.pendingMessages.size, 1);
});

test('native snapshot refresh respects deletions and monotonic counters', () => {
  const e = env(mobileCode);
  e.api.setPasskeys([{ ...passkey, counter: 9 }]);
  e.context.AndroidBridge = {
    loadVaultSnapshot: () => JSON.stringify({ passkeys: [passkey], totpEntries: [] }),
  };
  e.api.mergeNativeSnapshot();
  assert.equal(e.api.getPasskeys()[0].counter, 9);
  e.storage.set('sync_deletions', JSON.stringify([{ kind: 'passkey', id: 'p', deletedAt: 2 }]));
  e.api.mergeNativeSnapshot();
  assert.equal(e.api.getPasskeys().length, 0);
});

async function clients() {
  const b = await browser();
  const bg = env(backgroundCode);
  const owner = Object.create(bg.api.BackgroundService.prototype);
  owner.vaultJobs = Promise.resolve();
  let records = [];
  owner.loadPasskeys = async () => records;
  owner.savePasskeys = async (value) => {
    records = value;
  };
  b.s.vaultAdapter = owner.syncVaultAdapter();
  const mobile = env(mobileCode),
    m = new mobile.api.AndroidSync({ ...config });
  await m.deriveKeys();
  return { b, bg, owner, mobile, m };
}

test('signed browser/mobile bundles round-trip passkeys, HOTP counters and deletion', async () => {
  const { b, owner, mobile, m } = await clients();
  await owner.savePasskeys([passkey]);
  let bundle = await b.s.createEncryptedBundle([passkey], [totp]);
  let msg = {
    type: 'update',
    chainId: config.chainId,
    deviceId: 'browser',
    payload: { bundle },
    timestamp: Date.now(),
  };
  let event = await b.s.createNostrEvent(await b.s.encryptMessage(msg), 'update');
  await m.handleRelayMessage(JSON.stringify(['EVENT', 'test', event]));
  assert.equal(mobile.api.getPasskeys()[0].privateKey, passkey.privateKey);
  assert.equal(mobile.api.getTotpEntries()[0].secretB64, totp.secretB64);
  mobile.api.setPasskeys([{ ...passkey, counter: 7 }]);
  mobile.api.setTotpEntries([{ ...totp, counter: 7 }]);
  bundle = await m.createBundle();
  msg = {
    type: 'update',
    chainId: config.chainId,
    deviceId: 'mobile',
    payload: { bundle },
    timestamp: Date.now(),
  };
  event = await m.createEvent(await m.encryptMessage(msg), 'update');
  await b.s.handleWebSocketMessage(JSON.stringify(['EVENT', 'test', event]), { url: 'fixture' });
  assert.equal((await owner.loadPasskeys())[0].counter, 7);
  const snapshot = await b.s.vaultAdapter.getSnapshot();
  assert.equal(snapshot.totpEntries[0].counter, 7);
  m.mergeVault([], [], 'peer', [
    { kind: 'passkey', id: 'p', deletedAt: 2 },
    { kind: 'totp', id: 't', deletedAt: 2 },
  ]);
  bundle = await m.createBundle();
  msg.payload = { bundle };
  event = await m.createEvent(await m.encryptMessage(msg), 'update');
  await b.s.handleWebSocketMessage(JSON.stringify(['EVENT', 'test', event]), { url: 'fixture' });
  const deleted = await b.s.vaultAdapter.getSnapshot();
  assert.equal(deleted.passkeys.length, 0);
  assert.equal(deleted.totpEntries.length, 0);
  assert.equal(deleted.deletions.length, 2);
  await b.s.vaultAdapter.mergeRemote([passkey], [totp], 'old-client');
  assert.equal((await owner.loadPasskeys()).length, 0);
});

test('presence cannot replace a retained device snapshot', async () => {
  const { s } = await browser();
  const snapshot = await s.createNostrEvent('snapshot', 'update');
  const presence = await s.createNostrEvent('presence', 'announce');
  assert.notEqual(
    snapshot.tags.find((t) => t[0] === 'd')[1],
    presence.tags.find((t) => t[0] === 'd')[1]
  );
  assert.equal(snapshot.tags.find((t) => t[0] === 'h')[1], config.chainId);
});

test('browser deletion records use the stored id when credentialId differs', async () => {
  const { b, owner } = await clients();
  await owner.savePasskeys([{ ...passkey, credentialId: 'different' }]);
  owner.logSync = () => {};
  owner.incrementPendingChanges = async () => {};
  owner.triggerSync = async () => {};
  const result = await owner.handleDeletePasskey({ credentialId: 'different' });
  assert.equal(result.success, true);
  assert.equal((await b.s.vaultAdapter.getSnapshot()).deletions[0].id, 'p');
});

test('coalesced updates eventually send the newest queued snapshot', async () => {
  const { s } = await browser(),
    frames = [];
  s.relayConnections = [{ ws: { readyState: 1, send: (frame) => frames.push(JSON.parse(frame)) } }];
  s.lastBroadcastTime = Date.now();
  await s.broadcastMessage({ type: 'update', payload: { revision: 1 } });
  await s.broadcastMessage({ type: 'update', payload: { revision: 2 } });
  s.lastBroadcastTime = 0;
  await s.flushBroadcast();
  assert.equal((await s.decryptMessage(frames[0][1].content)).payload.revision, 2);
});

test('a returning mobile client retrieves a two-hour-old retained snapshot', async () => {
  const { b, owner, mobile, m } = await clients();
  await owner.savePasskeys([passkey]);
  const bundle = await b.s.createEncryptedBundle([passkey], []);
  const message = {
    type: 'update',
    chainId: config.chainId,
    deviceId: 'browser',
    timestamp: Date.now(),
    payload: { bundle },
  };
  const snapshot = await b.s.createNostrEvent(await b.s.encryptMessage(message), 'update');
  const presence = await b.s.createNostrEvent(
    await b.s.encryptMessage({ ...message, type: 'announce', payload: { action: 'online' } }),
    'announce'
  );
  const stored = new Map();
  for (const event of [snapshot, presence]) {
    stored.set(event.tags.find((t) => t[0] === 'd')[1], event);
  }
  mobile.context.Date = class extends Date {
    static now() {
      return Date.now() + 2 * 60 * 60 * 1000;
    }
  };
  const requests = [];
  m.ws = { send: (frame) => requests.push(JSON.parse(frame)) };
  m.subscribe();
  const filters = requests[0].slice(2);
  for (const event of stored.values()) {
    const matches = filters.some(
      (filter) =>
        (!filter.since || event.created_at >= filter.since) &&
        (!filter.authors || filter.authors.includes(event.pubkey)) &&
        Object.entries(filter)
          .filter(([key]) => key.startsWith('#'))
          .every(([key, values]) =>
            event.tags.some((t) => t[0] === key.slice(1) && values.includes(t[1]))
          )
    );
    if (matches) {
      await m.handleRelayMessage(JSON.stringify(['EVENT', 'test', event]));
    }
  }
  assert.equal(mobile.api.getPasskeys()[0].privateKey, passkey.privateKey);
});

test('tampered signed events cannot modify the mobile vault', async () => {
  const { b, mobile, m } = await clients();
  const bundle = await b.s.createEncryptedBundle([passkey], []);
  const event = await b.s.createNostrEvent(
    await b.s.encryptMessage({
      type: 'update',
      chainId: config.chainId,
      deviceId: 'browser',
      payload: { bundle },
    }),
    'update'
  );
  event.sig = '00'.repeat(64);
  await m.handleRelayMessage(JSON.stringify(['EVENT', 'test', event]));
  assert.equal(mobile.api.getPasskeys().length, 0);
});

test('restore succeeds even when the deleting device clock is ahead', () => {
  const e = env(mobileCode);
  e.storage.set(
    'sync_deletions',
    JSON.stringify([{ kind: 'passkey', id: 'p', deletedAt: Date.now() + 60000 }])
  );
  e.storage.set(
    'recycle_bin',
    JSON.stringify([{ kind: 'passkey', deletedAt: Date.now(), passkey }])
  );
  e.api.restoreFromBin(0);
  const m = new e.api.AndroidSync({ ...config });
  m.mergeVault([], [], 'peer');
  assert.equal(e.api.getPasskeys().length, 1);
});

test('an invalid signature cannot suppress a later valid copy of the event', async () => {
  const { b, mobile, m } = await clients();
  const bundle = await b.s.createEncryptedBundle([passkey], []);
  const event = await b.s.createNostrEvent(
    await b.s.encryptMessage({
      type: 'update',
      chainId: config.chainId,
      deviceId: 'browser',
      payload: { bundle },
    }),
    'update'
  );
  await m.handleRelayMessage(JSON.stringify(['EVENT', 'test', { ...event, sig: '00'.repeat(64) }]));
  await m.handleRelayMessage(JSON.stringify(['EVENT', 'test', event]));
  assert.equal(mobile.api.getPasskeys().length, 1);
});

test('a temporary storage failure does not permanently discard a snapshot', async () => {
  const { b, mobile, m } = await clients();
  mobile.api.setPasskeys([passkey]);
  const bundle = await m.createBundle();
  const event = await m.createEvent(
    await m.encryptMessage({
      type: 'update',
      chainId: config.chainId,
      deviceId: 'mobile',
      payload: { bundle },
    }),
    'update'
  );
  let merges = 0;
  b.s.vaultAdapter.mergeRemote = async () => {
    if (++merges === 1) {
      throw new Error('storage unavailable');
    }
  };
  const frame = JSON.stringify(['EVENT', 'test', event]);
  await b.s.handleWebSocketMessage(frame, { url: 'test' });
  await b.s.handleWebSocketMessage(frame, { url: 'test' });
  assert.equal(merges, 2);
});


test('equal revisions ignore property order and keep counter-independent winners', () => {
  const e = env(mobileCode), m = new e.api.AndroidSync({ ...config });
  const a = { ...passkey, label: 'a', counter: 99 };
  const z = { label: 'z', ...passkey, counter: 1 };
  e.api.setPasskeys([a]);
  m.mergeVault([z], [], 'peer');
  assert.equal(e.api.getPasskeys()[0].label, 'z');
  assert.equal(e.api.getPasskeys()[0].counter, 99);
  m.mergeVault([a], [], 'peer');
  assert.equal(e.api.getPasskeys()[0].label, 'z');
});

test('both readers reject unsupported bundle versions', async () => {
  const { b, m } = await clients();
  const bundle = await m.createBundle();
  for (const version of ['2.0', '3.0', '99.0', undefined]) {
    await assert.rejects(b.s.decryptBundle({ ...bundle, version }), /version/i);
    await assert.rejects(m.decryptBundle({ ...bundle, version }), /version/i);
  }
});

test('sync v4 cannot publish into legacy relay namespaces or use legacy keys', async () => {
  const { s } = await browser();
  for (const type of ['update', 'response', 'announce', 'request']) {
    const event = await s.createNostrEvent('test', type);
    assert.ok(event.tags.find(t => t[0] === 'd')[1].startsWith('pksync-v4-'));
  }
});

test('legacy sync salts are removed from mobile stored configuration', () => {
  const e = env(mobileCode);
  e.storage.set('sync_config', JSON.stringify(config));
  assert.equal('syncSalt' in e.api.getSyncConfig(), false);
  assert.equal('syncSalt' in JSON.parse(e.storage.get('sync_config')), false);
});

test('a stalled sync request does not block a passkey lookup', async () => {
  const e = env(backgroundCode);
  const owner = Object.create(e.api.BackgroundService.prototype);
  owner.vaultJobs = Promise.resolve();
  let release;
  owner.handleTriggerSync = () => new Promise(resolve => { release = resolve; });
  owner.handleListPasskeys = async () => ({ success: true });
  const sync = owner.handleMessage({ type: 'TRIGGER_SYNC' }, () => {});
  await new Promise(resolve => setImmediate(resolve));
  let replied = false;
  const lookup = owner.handleMessage({ type: 'LIST_PASSKEYS' }, () => { replied = true; });
  await new Promise(resolve => setImmediate(resolve));
  const completed = replied;
  release();
  await Promise.all([sync, lookup]);
  assert.equal(completed, true);
});

for (const platform of ['browser', 'mobile']) {
  test(`${platform} stops retrying an unacknowledged snapshot`, async () => {
    const e = platform === 'browser' ? await browser() : env(mobileCode);
    const s = e.s || new e.api.AndroidSync({ ...config });
    if (!e.s) await s.deriveKeys();
    const frames = [];
    const ws = { readyState: 1, send: frame => frames.push(JSON.parse(frame)) };
    if (e.s) s.relayConnections = [{ ws }]; else s.ws = ws;
    const send = () => e.s ? s.flushBroadcast() : s.flushMessages();
    await (e.s ? s.broadcastMessage({ type: 'update', payload: {} }) : s.broadcast({ type: 'update', payload: {} }));
    for (let i = 0; i < 12; i++) {
      e.context.Date = class extends Date { static now() { return Date.now() + (i + 1) * 600000; } };
      await send();
    }
    assert.ok(frames.length <= 5, `sent ${frames.length} times`);
    assert.ok(s.lastError, 'retry exhaustion must be visible');
    assert.equal(new Set(frames.map(frame => frame[1].id)).size, 1, 'retries reuse event IDs');
  });
}

test('large deletion history travels in bounded signed frames and reassembles', async () => {
  const { b, owner, mobile, m } = await clients();
  const deletions = Array.from({ length: 3000 }, (_, i) => ({ kind: 'passkey', id: `deleted-${i}`, deletedAt: 2 }));
  b.s.vaultAdapter.getSnapshot = async () => ({ passkeys: [], totpEntries: [], deletions });
  const frames = [];
  b.s.isConnected = true;
  b.s.relayConnections = [{ ws: { readyState: 1, send: frame => frames.push(JSON.parse(frame)) } }];
  await b.s.broadcastPasskeyUpdate([], []);
  assert.ok(frames.length > 1, 'large snapshot must be split');
  for (const frame of frames.reverse()) {
    assert.ok(Buffer.byteLength(JSON.stringify(frame)) <= 16384);
    await m.handleRelayMessage(JSON.stringify(['EVENT', 'test', frame[1]]));
  }
  assert.equal(JSON.parse(mobile.storage.get('sync_deletions')).length, deletions.length);
});
