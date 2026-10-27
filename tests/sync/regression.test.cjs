const { test, before } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const esbuild = require('esbuild');

let browserCode, mobileCode, backgroundCode, storageCode;
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
  storageCode = await bundle('src/crypto/secure-storage.ts', '\nexport { deriveKeyFromPassword };');
  backgroundCode = await bundle(
    'src/background/background.ts',
    '\nexport { BackgroundService };',
    'new BackgroundService();'
  );
  mobileCode = await bundle(
    'android/web/src/app.ts',
    '\nrender = () => {}; export { AndroidSync, getPasskeys, setPasskeys, getTotpEntries, setTotpEntries, mergeNativeSnapshot, restoreFromBin, getSyncConfig, issueHotpCode, renderTotpItem, state };',
    'void boot().catch'
  );
});

// Chrome's account of a message from the popup, an extension page.
const EXTENSION_ORIGIN = 'chrome-extension://fenkovaulttest';
const POPUP = { id: 'fenkovaulttest', url: `${EXTENSION_ORIGIN}/popup.html` };

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
      runtime: { getURL: (path) => `${EXTENSION_ORIGIN}/${path}` },
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
  const e = env(mobileCode),
    m = new e.api.AndroidSync({ ...config });
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
    assert.ok(event.tags.find((t) => t[0] === 'd')[1].startsWith('pksync-v4-'));
  }
});

test('legacy sync salts are removed from mobile stored configuration', () => {
  const e = env(mobileCode);
  e.storage.set('sync_config', JSON.stringify(config));
  assert.equal('syncSalt' in e.api.getSyncConfig(), false);
  assert.equal('syncSalt' in JSON.parse(e.storage.get('sync_config')), false);
});

// Relays that never open on their own; the test drives open/close by hand.
function unreachableRelays(code = browserCode) {
  const e = env(code);
  const sockets = [];
  e.context.WebSocket = class {
    static CONNECTING = 0;
    static OPEN = 1;
    constructor(url) {
      this.url = url;
      this.readyState = 0;
      this.closed = false;
      sockets.push(this);
    }
    send() {}
    close() {
      this.closed = true;
      this.readyState = 3;
    }
  };
  e.storage.set('custom_relays', ['wss://a.test', 'wss://b.test']);
  const s = e.api.SyncService ? new e.api.SyncService() : null;
  if (s) s.log = () => {};
  const fire = (delay) => {
    for (const [id, t] of [...e.timers]) {
      if (delay === undefined || t.delay === delay) {
        e.timers.delete(id);
        t.fn();
      }
    }
  };
  const until = async (condition) => {
    for (let i = 0; i < 400 && !condition(); i++) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.ok(condition(), 'timed out waiting for sync service');
  };
  // initialize() resolves after a 12s grace period when no relay opens.
  const settle = async (promise) => {
    let done = false;
    promise.then(() => (done = true));
    await until(() => {
      fire(12000);
      return done;
    });
  };
  return { e, s, sockets, live: () => sockets.filter((ws) => !ws.closed), fire, until, settle };
}

test('re-initializing a disconnected chain reuses one socket per relay', async () => {
  const { s, sockets, live, fire, settle } = unreachableRelays();
  let derivations = 0;
  const derive = s.deriveKeys.bind(s);
  s.deriveKeys = (seedHash) => {
    derivations++;
    return derive(seedHash);
  };
  // Startup and a vault change race while the relays are unreachable.
  const first = s.initialize(config.chainId, 'browser', config.seedHash);
  const second = s.initialize(config.chainId, 'browser', config.seedHash);
  await settle(Promise.all([first, second]));
  assert.equal(live().length, 2, 'overlapping initialization opened a second set of sockets');

  // Every relay drops and schedules a reconnect, then another vault change
  // re-initializes while still disconnected.
  for (const ws of live()) {
    ws.close();
    ws.onclose({ code: 1006, reason: '' });
  }
  await settle(s.initialize(config.chainId, 'browser', config.seedHash));
  fire(5000);
  assert.equal(live().length, 2, 'orphaned reconnect timers opened extra sockets');
  assert.equal(derivations, 1, 'reconnecting the same chain must reuse its keys');

  await s.disconnect();
  fire();
  assert.equal(live().length, 0, 'disconnect left sockets open');
  assert.ok(
    sockets.every((ws) => ws.closed),
    'every socket must be closed'
  );
});

test('initializing another chain closes the previous relay sockets', async () => {
  const { s, live, settle } = unreachableRelays();
  await settle(s.initialize(config.chainId, 'browser', config.seedHash));
  const previous = live();
  await settle(s.initialize('cd'.repeat(16), 'browser', 'cd'.repeat(32)));
  assert.ok(
    previous.every((ws) => ws.closed),
    'sockets of the previous chain stayed open'
  );
  assert.equal(live().length, 2);
});

test('disconnect during initialization leaves no keys or sockets behind', async () => {
  const { s, sockets, until, settle } = unreachableRelays();
  let release;
  const derive = s.deriveKeys.bind(s);
  s.deriveKeys = (seedHash) =>
    new Promise((resolve) => {
      release = () => resolve(derive(seedHash));
    });
  const init = s.initialize(config.chainId, 'browser', config.seedHash);
  await until(() => release);
  await s.disconnect();
  release();
  await settle(init);
  assert.equal(s.nostrPrivateKey, null);
  assert.equal(s.encryptionKey, null);
  assert.equal(sockets.length, 0);
  assert.equal(s.relayConnections.length, 0);
});

test('a restarted service worker keeps the persisted sync status', async () => {
  const e = env(backgroundCode);
  const listener = { addListener() {} };
  e.context.chrome.runtime = {
    onMessage: listener,
    onInstalled: listener,
    onStartup: listener,
    onSuspend: listener,
  };
  e.storage.set('sync_status', { pendingChanges: 3, lastSyncSuccess: 1234, lastSyncAttempt: 5678 });
  // A fresh worker: the first writes are startup sync and a cold-start change.
  const owner = new e.api.BackgroundService();
  await owner.updateSyncStatus({ connectionStatus: 'connected' });
  await Promise.all([owner.incrementPendingChanges(), owner.incrementPendingChanges()]);
  const stored = e.storage.get('sync_status');
  assert.equal(stored.pendingChanges, 5);
  assert.equal(stored.lastSyncSuccess, 1234);
  assert.equal(stored.lastSyncAttempt, 5678);
  assert.equal(stored.connectionStatus, 'connected');
});

function syncOwner() {
  const relays = unreachableRelays(backgroundCode);
  const owner = Object.create(relays.e.api.BackgroundService.prototype);
  owner.vaultJobs = Promise.resolve();
  owner.syncStatus = { pendingChanges: 0, lastError: 'Relay rejected update' };
  owner.loadPasskeys = async () => [passkey];
  const { seedHash, ...publicConfig } = config;
  relays.e.storage.set('sync_config', publicConfig);
  return { ...relays, owner, seedHash };
}

test('sync now while offline does not report a healthy connection', async () => {
  const { owner, e } = syncOwner();
  // A PIN-protected vault keeps the seed out of raw storage; locked, it has none.
  await owner.triggerSync();
  const stored = e.storage.get('sync_status');
  assert.notEqual(stored.connectionStatus, 'connected');
  assert.equal(stored.lastError, 'Relay rejected update');
  assert.equal(stored.pendingChanges, 1);
});

test('sync now reconnects a PIN-protected vault from its encrypted seed', async () => {
  const { owner, e, live, settle, seedHash } = syncOwner();
  owner.resolveSyncSeedHash = async (stored) => {
    assert.equal(stored.seedHash, undefined);
    return seedHash;
  };
  await settle(owner.triggerSync());
  assert.equal(live().length, 2, 'triggerSync must start the relays with the unlocked seed');
  assert.equal(e.storage.get('sync_status').connectionStatus, 'disconnected');

  const [ws] = live();
  ws.readyState = 1;
  ws.onopen();
  await owner.triggerSync();
  const stored = e.storage.get('sync_status');
  assert.equal(stored.connectionStatus, 'connected');
  assert.equal(stored.lastError, null);
});

test('browser HOTP next-code advances, persists and publishes the counter', async () => {
  const e = env(backgroundCode);
  const owner = Object.create(e.api.BackgroundService.prototype);
  owner.vaultJobs = Promise.resolve();
  owner.syncStatus = { pendingChanges: 0 };
  owner.updateSyncStatus = async (update) =>
    Object.assign(
      owner.syncStatus,
      typeof update === 'function' ? update(owner.syncStatus) : update
    );
  let syncs = 0;
  owner.triggerSync = async () => {
    syncs++;
  };
  const secretB64 = Buffer.from('12345678901234567890').toString('base64');
  e.storage.set('totp_entries', [
    { id: 'h', type: 'hotp', secretB64, algorithm: 'SHA1', digits: 6, counter: 0, createdAt: 1 },
  ]);
  const send = (type) =>
    new Promise((resolve) => owner.handleMessage({ type, payload: { id: 'h' } }, resolve, POPUP));
  // Rendering a code is a pure read and must not consume a counter value.
  assert.equal((await send('GENERATE_TOTP_CODE')).code, '755224');
  assert.equal((await send('GENERATE_TOTP_CODE')).code, '755224');
  assert.equal(e.storage.get('totp_entries')[0].counter, 0);
  // RFC 4226 Appendix D, counts 0 and 1.
  assert.equal((await send('NEXT_HOTP_CODE')).code, '755224');
  assert.equal((await send('NEXT_HOTP_CODE')).code, '287082');
  assert.equal(e.storage.get('totp_entries')[0].counter, 2);
  assert.equal(syncs, 2);
  assert.equal(owner.syncStatus.pendingChanges, 2);
});

test('mobile HOTP next-code advances and persists the counter', () => {
  const e = env(mobileCode);
  const secretB64 = Buffer.from('12345678901234567890').toString('base64');
  e.api.setTotpEntries([
    { id: 'h', type: 'hotp', secretB64, algorithm: 'SHA1', digits: 6, counter: 0, createdAt: 1 },
  ]);
  assert.equal(e.api.issueHotpCode('h'), '755224');
  assert.equal(e.api.issueHotpCode('h'), '287082');
  assert.equal(e.api.getTotpEntries()[0].counter, 2);
  assert.equal(e.api.issueHotpCode('missing'), null);
});

test('mobile vault markup shows synced 2FA fields as text', () => {
  // Synced entries are not normalised like imported ones, and any device
  // holding the recovery phrase can publish them.
  const e = env(mobileCode);
  const hostile = '<img src=x onerror=alert(1)>';
  const secretB64 = Buffer.from('12345678901234567890').toString('base64');
  const hotp = {
    id: 'h',
    type: 'hotp',
    secretB64,
    algorithm: hostile,
    digits: hostile,
    counter: hostile,
    createdAt: 1,
  };
  const totp = {
    id: 't',
    type: hostile,
    secretB64,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    createdAt: 1,
  };
  e.api.state.expanded.add('h');
  e.api.state.expanded.add('t');
  for (const markup of [e.api.renderTotpItem(hotp), e.api.renderTotpItem(totp)]) {
    assert.doesNotMatch(markup, /<img/i);
    assert.match(markup, /&lt;img/i);
  }
});

test('a stalled sync request does not block a passkey lookup', async () => {
  const e = env(backgroundCode);
  const owner = Object.create(e.api.BackgroundService.prototype);
  owner.vaultJobs = Promise.resolve();
  let release;
  owner.handleTriggerSync = () =>
    new Promise((resolve) => {
      release = resolve;
    });
  owner.handleListPasskeys = async () => ({ success: true });
  const sync = owner.handleMessage({ type: 'TRIGGER_SYNC' }, () => {}, POPUP);
  await new Promise((resolve) => setImmediate(resolve));
  let replied = false;
  const lookup = owner.handleMessage(
    { type: 'LIST_PASSKEYS' },
    () => {
      replied = true;
    },
    POPUP
  );
  await new Promise((resolve) => setImmediate(resolve));
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
    const ws = { readyState: 1, send: (frame) => frames.push(JSON.parse(frame)) };
    if (e.s) s.relayConnections = [{ ws }];
    else s.ws = ws;
    const send = () => (e.s ? s.flushBroadcast() : s.flushMessages());
    await (e.s
      ? s.broadcastMessage({ type: 'update', payload: {} })
      : s.broadcast({ type: 'update', payload: {} }));
    for (let i = 0; i < 12; i++) {
      e.context.Date = class extends Date {
        static now() {
          return Date.now() + (i + 1) * 600000;
        }
      };
      await send();
    }
    assert.ok(frames.length <= 5, `sent ${frames.length} times`);
    assert.ok(s.lastError, 'retry exhaustion must be visible');
    assert.equal(new Set(frames.map((frame) => frame[1].id)).size, 1, 'retries reuse event IDs');
  });
}

test('large deletion history travels in bounded signed frames and reassembles', async () => {
  const { b, owner, mobile, m } = await clients();
  const deletions = Array.from({ length: 3000 }, (_, i) => ({
    kind: 'passkey',
    id: `deleted-${i}`,
    deletedAt: 2,
  }));
  b.s.vaultAdapter.getSnapshot = async () => ({ passkeys: [], totpEntries: [], deletions });
  const frames = [];
  b.s.isConnected = true;
  b.s.relayConnections = [
    { ws: { readyState: 1, send: (frame) => frames.push(JSON.parse(frame)) } },
  ];
  await b.s.broadcastPasskeyUpdate([], []);
  assert.ok(frames.length > 1, 'large snapshot must be split');
  for (const frame of frames.reverse()) {
    assert.ok(Buffer.byteLength(JSON.stringify(frame)) <= 16384);
    await m.handleRelayMessage(JSON.stringify(['EVENT', 'test', frame[1]]));
  }
  assert.equal(JSON.parse(mobile.storage.get('sync_deletions')).length, deletions.length);
});

test('password derivation yields and remains compatible with existing encryption', async () => {
  const e = env(storageCode);
  let derivations = 0;
  e.context.crypto = {
    ...webcrypto,
    subtle: {
      importKey: (...args) => webcrypto.subtle.importKey(...args),
      deriveBits: (...args) => {
        derivations++;
        return webcrypto.subtle.deriveBits(...args);
      },
    },
  };
  const salt = new Uint8Array(32).fill(7);
  const key = await e.api.deriveKeyFromPassword('123456', salt);
  const expected = require('node:crypto').pbkdf2Sync('123456', salt, 100000, 32, 'sha256');
  assert.equal(Buffer.from(key).toString('hex'), expected.toString('hex'));
  assert.equal(derivations, 1, 'password work must run in asynchronous WebCrypto');
});

test('heartbeat cannot restart exhausted delivery; explicit retry can', async () => {
  const { b, m } = await clients();
  const frames = [];
  b.s.relayConnections = [
    { ws: { readyState: 1, send: (frame) => frames.push(JSON.parse(frame)) } },
  ];
  const message = { type: 'update', payload: { bundle: await m.createBundle() } };
  await b.s.broadcastMessage(message);
  for (let i = 0; i < 6; i++) {
    b.context.Date = class extends Date {
      static now() {
        return Date.now() + (i + 1) * 600000;
      }
    };
    await b.s.flushBroadcast();
  }
  assert.equal(frames.length, 5);
  await b.s.broadcastMessage({ ...message, payload: { bundle: await m.createBundle() } });
  assert.equal(frames.length, 5);
  b.s.retryPending();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(frames.length, 6);
});

test('chunked snapshots need all acknowledgements before reporting success', async () => {
  const { b } = await clients();
  let published = 0;
  const deletions = Array.from({ length: 1000 }, (_, i) => ({
    kind: 'passkey',
    id: `deleted-${i}`,
    deletedAt: 2,
  }));
  b.s.vaultAdapter.getSnapshot = async () => ({ passkeys: [], totpEntries: [], deletions });
  b.s.vaultAdapter.onPublished = async () => published++;
  const frames = [];
  const conn = { ws: { readyState: 1, send: (frame) => frames.push(JSON.parse(frame)) } };
  b.s.relayConnections = [conn];
  b.s.isConnected = true;
  await b.s.broadcastPasskeyUpdate([], []);
  assert.ok(frames.length > 1);
  for (const frame of frames.slice(1)) {
    await b.s.handleWebSocketMessage(JSON.stringify(['OK', frame[1].id, true, '']), conn);
    assert.equal(published, 0);
  }
  await b.s.handleWebSocketMessage(JSON.stringify(['OK', 'wrong-id', true, '']), conn);
  assert.equal(published, 0);
  await b.s.handleWebSocketMessage(JSON.stringify(['OK', frames[0][1].id, true, '']), conn);
  assert.equal(published, 1);
});

test('offline recovery fetches missing chunk addresses beyond relay history limits', async () => {
  const { b, mobile, m } = await clients();
  const deletions = Array.from({ length: 1000 }, (_, i) => ({
    kind: 'passkey',
    id: `deleted-${i}`,
    deletedAt: 2,
  }));
  b.s.vaultAdapter.getSnapshot = async () => ({ passkeys: [], totpEntries: [], deletions });
  const frames = [],
    requests = [];
  b.s.relayConnections = [
    { ws: { readyState: 1, send: (frame) => frames.push(JSON.parse(frame)) } },
  ];
  b.s.isConnected = true;
  await b.s.broadcastPasskeyUpdate([], []);
  m.ws = { send: (frame) => requests.push(JSON.parse(frame)) };
  await m.handleRelayMessage(JSON.stringify(['EVENT', 'history', frames[0][1]]));
  assert.equal(mobile.storage.has('sync_deletions'), false, 'partial snapshots cannot apply');
  const addresses = requests.flatMap((frame) => frame[2]['#d']);
  for (const frame of frames.slice(1)) {
    assert.ok(addresses.includes(frame[1].tags.find((t) => t[0] === 'd')[1]));
    await m.handleRelayMessage(JSON.stringify(['EVENT', 'parts_test', frame[1]]));
  }
  assert.equal(JSON.parse(mobile.storage.get('sync_deletions')).length, deletions.length);
});

for (const fixture of require('./merge-fixtures.json')) {
  test(`shared native/web merge fixture: ${fixture.name}`, () => {
    const e = env(mobileCode),
      m = new e.api.AndroidSync({ ...config });
    for (const [local, remote] of [
      [fixture.local, fixture.remote],
      [fixture.remote, fixture.local],
    ]) {
      e.api.setPasskeys([local]);
      m.mergeVault([remote], [], 'peer');
      assert.equal(e.api.getPasskeys()[0].label, fixture.winner);
      assert.equal(e.api.getPasskeys()[0].counter, fixture.counter);
      if ('backupEligible' in fixture) {
        assert.equal(e.api.getPasskeys()[0].backupEligible, fixture.backupEligible);
      }
    }
  });
}

test('acknowledging presence cannot hide an exhausted snapshot', async () => {
  const { s, context } = await browser();
  const frames = [];
  const conn = { ws: { readyState: 1, send: (frame) => frames.push(JSON.parse(frame)) } };
  s.relayConnections = [conn];
  await s.broadcastMessage({ type: 'update', payload: {} });
  for (let i = 0; i < 6; i++) {
    context.Date = class extends Date {
      static now() {
        return Date.now() + (i + 1) * 600000;
      }
    };
    await s.flushBroadcast();
  }
  await s.broadcastMessage({ type: 'announce', payload: { action: 'online' } });
  await s.handleWebSocketMessage(JSON.stringify(['OK', frames.at(-1)[1].id, true, '']), conn);
  assert.ok(s.getStatus().lastError, 'presence ACK is not a snapshot ACK');
});

const BITWARDEN_GUID = '674880d4-06ed-1af1-e8dd-2d901d9dbd3d';
const DECODED_ID = 'Z0iA1AbtGvHo3S2QHZ29PQ';
const bitwardenImport = { ...passkey, id: BITWARDEN_GUID, credentialId: BITWARDEN_GUID };

// Arrays built inside the VM fail deepStrictEqual against this realm's arrays.
const plain = (value) => JSON.parse(JSON.stringify(value));

function quietOwner(owner) {
  Object.assign(owner, {
    logSync() {},
    logWebAuthn() {},
    incrementPendingChanges: async () => {},
    triggerSync: async () => {},
  });
}

test('Bitwarden credential IDs are re-keyed and the repair converges on mobile', async () => {
  const { b, owner, mobile, m } = await clients();
  quietOwner(owner);
  await owner.savePasskeys([bitwardenImport]);
  mobile.api.setPasskeys([bitwardenImport]);

  await owner.repairStoredCredentialIds();
  const snapshot = await b.s.vaultAdapter.getSnapshot();
  assert.deepEqual(plain(snapshot.passkeys.map((entry) => [entry.id, entry.credentialId])), [
    [DECODED_ID, DECODED_ID],
  ]);
  assert.deepEqual(plain(snapshot.deletions.map((entry) => entry.id)), [BITWARDEN_GUID]);

  m.mergeVault(snapshot.passkeys, [], 'browser', snapshot.deletions);
  assert.deepEqual(plain(mobile.api.getPasskeys().map((entry) => [entry.id, entry.privateKey])), [
    [DECODED_ID, passkey.privateKey],
  ]);
});

test('browser re-keys Bitwarden IDs a peer on an older build still sends', async () => {
  const { owner } = await clients();
  quietOwner(owner);
  await owner.syncVaultAdapter().mergeRemote([bitwardenImport], [], 'old-peer', []);
  assert.deepEqual(plain((await owner.loadPasskeys()).map((entry) => entry.id)), [DECODED_ID]);
});

test('browser refuses a new passkey only when the site excludes a stored one', async () => {
  const { owner } = await clients();
  quietOwner(owner);
  await owner.savePasskeys([{ ...passkey, id: DECODED_ID, credentialId: DECODED_ID }]);
  const register = (excludeCredentials) =>
    owner.handleCreatePasskey({
      publicKey: {
        rp: { id: 'example.com', name: 'Example' },
        rpId: 'example.com',
        user: { id: 'dXNlcg', name: 'ali', displayName: 'Ali' },
        challenge: 'AAAA',
        excludeCredentials,
      },
      origin: 'https://example.com',
    });

  const second = await register([{ id: 'b3RoZXI', type: 'public-key' }]);
  assert.equal(second.success, true, second.error);
  const excluded = await register([{ id: DECODED_ID, type: 'public-key' }]);
  assert.equal(excluded.name, 'InvalidStateError');
  assert.equal((await owner.loadPasskeys()).length, 2);
});

// A fresh SecureStorage over the same chrome.storage is what a restarted
// service worker sees: local and session storage survive, memory does not.
function vaultWorker(shared) {
  const e = env(storageCode);
  const session = shared?.session ?? new Map();
  const alarms = shared?.alarms ?? new Map();
  const area = (map) => ({
    get: async (k) => ({ [k]: map.get(k) }),
    set: async (o) => Object.entries(o).forEach(([k, v]) => map.set(k, v)),
    remove: async (k) => [].concat(k).forEach((key) => map.delete(key)),
  });
  if (shared) {
    for (const [k, v] of shared.storage) e.storage.set(k, v);
  }
  e.context.chrome.storage.local = area(e.storage);
  e.context.chrome.storage.session = area(session);
  e.context.chrome.alarms = {
    create: async (name, info) => alarms.set(name, info),
    clear: async (name) => alarms.delete(name),
  };
  const vault = new e.api.SecureStorage();
  const settle = () => new Promise((resolve) => setImmediate(resolve));
  const later = (ms) => {
    const now = Date.now() + ms;
    e.context.Date = class extends Date {
      static now() {
        return now;
      }
    };
  };
  return { ...e, session, alarms, vault, settle, later };
}

test('an unlock survives a service worker restart until the auto-lock timeout', async () => {
  const first = vaultWorker();
  first.storage.set('auto_lock_timeout', 30);
  assert.equal(await first.vault.initialize('123456'), true);
  await first.vault.storePasskeys([passkey]);
  await first.settle();
  const deadline = first.alarms.get('passext-auto-lock').when;
  assert.ok(Math.abs(deadline - (Date.now() + 30 * 60000)) < 5000, 'alarm at the timeout');

  const restarted = vaultWorker(first);
  restarted.later(29 * 60000);
  assert.equal(await restarted.vault.restoreSession(), true);
  assert.equal((await restarted.vault.getPasskeys())[0].privateKey, passkey.privateKey);

  await restarted.settle();
  const extended = vaultWorker(first);
  extended.later(31 * 60000);
  assert.equal(await extended.vault.restoreSession(), true, 'activity after restart counts');

  const expired = vaultWorker(first);
  expired.later(60 * 60000);
  assert.equal(await expired.vault.restoreSession(), false);
  await expired.settle();
  assert.equal(expired.session.size, 0, 'expired key is dropped from session storage');
});

test('the auto-lock alarm locks a live worker and reports it', async () => {
  const w = vaultWorker();
  assert.equal(await w.vault.initialize('123456'), true);
  let autoLocked = 0;
  w.vault.onAutoLock = () => autoLocked++;
  await w.vault.lockIfIdle();
  assert.equal(w.vault.isStorageUnlocked(), true, 'not idle yet');
  w.later(31 * 60000);
  await w.vault.lockIfIdle();
  await w.settle();
  assert.equal(w.vault.isStorageUnlocked(), false);
  assert.equal(autoLocked, 1);
  assert.equal(w.session.size + w.alarms.size, 0);
});

test('"Never" keeps the vault unlocked instead of locking at once', async () => {
  const w = vaultWorker();
  w.storage.set('auto_lock_timeout', 0);
  await w.vault.restoreSession();
  assert.equal(await w.vault.initialize('123456'), true);
  await w.settle();
  assert.equal(w.timers.size, 0, 'no lock timer');
  assert.equal(w.alarms.size, 0, 'no lock alarm');
  const restarted = vaultWorker(w);
  restarted.later(7 * 24 * 3600000);
  assert.equal(await restarted.vault.restoreSession(), true);
});

test('a session from before a PIN change no longer unlocks', async () => {
  const w = vaultWorker();
  assert.equal(await w.vault.initialize('111111'), true);
  await w.settle();
  const stale = w.session.get('passext_unlocked_session');
  assert.equal(await w.vault.changeMasterPassword('111111', '222222'), true);
  await w.settle();
  assert.notEqual(w.session.get('passext_unlocked_session').key, stale.key);
  w.session.set('passext_unlocked_session', stale);
  assert.equal(await vaultWorker(w).vault.restoreSession(), false);
});

test('locking clears the saved session and alarm', async () => {
  const w = vaultWorker();
  assert.equal(await w.vault.initialize('123456'), true);
  await w.settle();
  assert.equal(w.session.size, 1);
  w.vault.lock();
  await w.settle();
  assert.equal(w.session.size + w.alarms.size, 0);
  assert.equal(await vaultWorker(w).vault.restoreSession(), false);
});

test('messages wait for the restored session before checking the lock', async () => {
  const e = env(backgroundCode);
  const owner = Object.create(e.api.BackgroundService.prototype);
  owner.vaultJobs = Promise.resolve();
  let restore;
  owner.sessionRestored = new Promise((resolve) => {
    restore = resolve;
  });
  owner.handleListPasskeys = async () => ({ success: true });
  let replied = false;
  const lookup = owner.handleMessage(
    { type: 'LIST_PASSKEYS' },
    () => {
      replied = true;
    },
    POPUP
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(replied, false);
  restore();
  await lookup;
  assert.equal(replied, true);
});

async function backgroundWithVault(records, stored = {}) {
  const e = env(backgroundCode);
  const values = new Map(Object.entries(stored));
  e.context.chrome.storage.local.get = async (keys) => {
    const out = {};
    for (const key of Array.isArray(keys) ? keys : [keys]) {
      if (values.has(key)) out[key] = values.get(key);
    }
    return out;
  };
  e.context.chrome.storage.local.set = async (items) =>
    Object.entries(items).forEach(([key, value]) => values.set(key, value));
  const owner = Object.create(e.api.BackgroundService.prototype);
  owner.vaultJobs = Promise.resolve();
  owner.loadPasskeys = async () => records;
  owner.savePasskeys = async (next) => {
    records = next;
  };
  owner.logWebAuthn = async () => {};
  owner.logSync = () => {};
  owner.incrementPendingChanges = async () => {};
  owner.triggerSync = () => {};
  return { owner, values, records: () => records };
}

async function vaultKey() {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', pair.privateKey));
  return pkcs8.toString('base64');
}

function signedFlags(response) {
  return Buffer.from(response.credential.response.authenticatorData, 'base64')[32];
}

const BE = 0x08;
const BS = 0x10;
const getRequest = {
  origin: 'https://tele.example.com',
  publicKey: { challenge: 'Y2hhbGxlbmdl', rpId: 'tele.example.com' },
};

test("sign-in uses the passkey's own backup flags, whatever the global toggles say", async () => {
  const privateKey = await vaultKey();
  const base = { rpId: 'tele.example.com', privateKey, createdAt: 1, counter: 0, user: {} };
  const { owner } = await backgroundWithVault(
    [
      { ...base, id: 'synced', backupEligible: true, backupState: true, backupSource: 'imported' },
      { ...base, id: 'bound', backupEligible: false, backupState: false, backupSource: 'created' },
    ],
    { webauthn_flags: { backupEligible: false, backupState: false } }
  );

  const synced = await owner.handleGetPasskey({ ...getRequest, selectedPasskeyId: 'synced' });
  assert.equal(signedFlags(synced) & (BE | BS), BE | BS);
  const bound = await owner.handleGetPasskey({ ...getRequest, selectedPasskeyId: 'bound' });
  assert.equal(signedFlags(bound) & (BE | BS), 0);
});

test('a passkey without flags signs with the pre-upgrade snapshot', async () => {
  const privateKey = await vaultKey();
  const record = { id: 'old', rpId: 'tele.example.com', privateKey, createdAt: 1, counter: 0 };
  const withSnapshot = await backgroundWithVault([{ ...record }], {
    webauthn_backup_snapshot: { backupEligible: true, backupState: true },
  });
  const response = await withSnapshot.owner.handleGetPasskey(getRequest);
  assert.equal(signedFlags(response) & (BE | BS), BE | BS);

  const noSnapshot = await backgroundWithVault([{ ...record }]);
  assert.equal(signedFlags(await noSnapshot.owner.handleGetPasskey(getRequest)) & (BE | BS), 0);
});

test('upgrade stamps the toggles in force onto existing passkeys, once', async () => {
  const vault = await backgroundWithVault(
    [{ id: 'old', rpId: 'tele.example.com', privateKey: 'k', createdAt: 1, counter: 0 }],
    { webauthn_flags: { backupEligible: true, backupState: true } }
  );
  await vault.owner.stampLegacyBackupFlags();
  assert.deepEqual(JSON.parse(JSON.stringify(vault.records()[0])), {
    id: 'old',
    rpId: 'tele.example.com',
    privateKey: 'k',
    createdAt: 1,
    counter: 0,
    backupEligible: true,
    backupState: true,
    backupSource: 'legacy',
  });
  assert.deepEqual(JSON.parse(JSON.stringify(vault.values.get('webauthn_backup_snapshot'))), {
    backupEligible: true,
    backupState: true,
  });

  // Turning the toggles off afterwards only affects new passkeys.
  vault.values.set('webauthn_flags', { backupEligible: false, backupState: false });
  await vault.owner.stampLegacyBackupFlags();
  assert.equal(vault.records()[0].backupEligible, true);
});

test('a new passkey records the flags it registered with', async () => {
  const vault = await backgroundWithVault([], {});
  const response = await vault.owner.handleCreatePasskey({
    origin: 'https://tele.example.com',
    publicKey: {
      challenge: 'Y2hhbGxlbmdl',
      rp: { id: 'tele.example.com', name: 'Teleport' },
      user: { id: 'dXNlcg', name: 'colin', displayName: 'colin' },
    },
  });
  assert.equal(response.success, true);
  const [created] = vault.records();
  assert.equal(created.backupEligible, true);
  assert.equal(created.backupState, false);
  assert.equal(created.backupSource, 'created');
  const attestedFlags = Buffer.from(response.credential.response.authenticatorData, 'base64')[32];
  assert.equal(attestedFlags & (BE | BS), BE);
});

test('the per-passkey switch sets both flags, marks the choice and bumps the revision', async () => {
  const vault = await backgroundWithVault([
    {
      id: 'p',
      rpId: 'tele.example.com',
      privateKey: 'k',
      createdAt: 1,
      updatedAt: 5,
      counter: 0,
      backupEligible: false,
      backupState: false,
      backupSource: 'legacy',
    },
  ]);
  const result = await vault.owner.handleSetPasskeyBackup({ credentialId: 'p', synced: true });
  assert.equal(result.success, true);
  const [record] = vault.records();
  assert.equal(record.backupEligible, true);
  assert.equal(record.backupState, true);
  assert.equal(record.backupSource, 'manual');
  assert.ok(record.updatedAt > 5);
});
