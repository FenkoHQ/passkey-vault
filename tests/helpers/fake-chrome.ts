/**
 * An in-memory `chrome` namespace with the semantics the extension relies on,
 * plus switches to break it on purpose.
 *
 * Storage values go through a JSON round trip, as chrome.storage serialises
 * them. Runtime messages do too: Chrome sends extension messages as JSON, so
 * an ArrayBuffer arrives as `{}` and a test that skipped the round trip would
 * pass where the browser fails.
 *
 * Faults are matched per call: a storage area and operation, an optional
 * predicate on the keys or items, and what to do instead (throw, or never
 * settle, which is what a terminated service worker looks like from inside).
 */

export type StorageData = Record<string, unknown>;
type StorageOp = 'get' | 'set' | 'remove' | 'clear';
type AreaName = 'local' | 'session';

export interface StorageFault {
  area?: AreaName;
  op: StorageOp;
  /** Keys being read or removed, or the keys of the items being written. */
  match?: (keys: string[], items?: StorageData) => boolean;
  /** Reject with this error. */
  error?: Error;
  /** Never settle, like a call cut off by a terminated worker. */
  hang?: boolean;
  /** How many matching calls to affect; unlimited when absent. */
  times?: number;
}

export interface MessageSender {
  id: string;
  url?: string;
  origin?: string;
  tab?: { id: number; url?: string };
  frameId?: number;
}

type MessageListener = (
  message: unknown,
  sender: MessageSender,
  sendResponse: (response?: unknown) => void
) => unknown;

type ChangeListener = (changes: Record<string, unknown>, areaName: string) => void;

export const EXTENSION_ID = 'fenkovaulttestextensionidaaaaaaa';
export const EXTENSION_ORIGIN = `chrome-extension://${EXTENSION_ID}`;

const clone = <T>(value: T): T =>
  value === undefined ? value : (JSON.parse(JSON.stringify(value)) as T);

/** The error Chrome reports when a message's receiver goes away. */
export const PORT_CLOSED = 'The message port closed before a response was received.';
export const NO_RECEIVER = 'Could not establish connection. Receiving end does not exist.';

class FakeStorageArea {
  readonly data: StorageData = {};

  constructor(
    private readonly name: AreaName,
    private readonly chrome: FakeChrome
  ) {}

  private keysOf(keys: unknown): { list: string[]; defaults: StorageData } {
    if (keys == null) return { list: Object.keys(this.data), defaults: {} };
    if (typeof keys === 'string') return { list: [keys], defaults: {} };
    if (Array.isArray(keys)) return { list: keys.map(String), defaults: {} };
    const defaults = keys as StorageData;
    return { list: Object.keys(defaults), defaults };
  }

  async get(keys?: unknown): Promise<StorageData> {
    const { list, defaults } = this.keysOf(keys);
    await this.chrome.checkFault(this.name, 'get', list);
    const result: StorageData = {};
    for (const key of list) {
      if (this.data[key] !== undefined) result[key] = clone(this.data[key]);
      else if (defaults[key] !== undefined) result[key] = clone(defaults[key]);
    }
    return result;
  }

  async set(items: StorageData): Promise<void> {
    const keys = Object.keys(items);
    await this.chrome.checkFault(this.name, 'set', keys, items);
    const changes: Record<string, unknown> = {};
    for (const key of keys) {
      const value = clone(items[key]);
      changes[key] = { oldValue: this.data[key], newValue: value };
      this.data[key] = value;
    }
    this.chrome.emitChange(changes, this.name);
  }

  async remove(keys: string | string[]): Promise<void> {
    const list = Array.isArray(keys) ? keys : [keys];
    await this.chrome.checkFault(this.name, 'remove', list);
    const changes: Record<string, unknown> = {};
    for (const key of list) {
      if (key in this.data) {
        changes[key] = { oldValue: this.data[key] };
        delete this.data[key];
      }
    }
    this.chrome.emitChange(changes, this.name);
  }

  async clear(): Promise<void> {
    await this.chrome.checkFault(this.name, 'clear', Object.keys(this.data));
    for (const key of Object.keys(this.data)) delete this.data[key];
  }

  /** Replace the whole area, outside of any fault, for test set-up. */
  seed(items: StorageData): void {
    for (const key of Object.keys(this.data)) delete this.data[key];
    Object.assign(this.data, clone(items));
  }
}

interface WorkerGeneration {
  listeners: MessageListener[];
  /** windows.onRemoved and tabs.onRemoved listeners the worker added. */
  windowRemoved: Array<(windowId: number) => void>;
  tabRemoved: Array<(tabId: number) => void>;
  alive: boolean;
  /** Rejecters for messages this generation has not answered yet. */
  pending: Set<(error: Error) => void>;
}

export class FakeChrome {
  readonly faults: StorageFault[] = [];
  private changeListeners: ChangeListener[] = [];
  private worker: WorkerGeneration = this.generation();
  private contentListeners: MessageListener[] = [];
  private loadingWorker = false;
  /** Every message the background received, as it arrived (after JSON). */
  readonly sentToBackground: Array<{ message: Record<string, unknown>; sender: MessageSender }> =
    [];
  /** Every message the background sent to a tab, in order. */
  readonly sentToTabs: Array<{
    tabId: number;
    frameId?: number;
    message: Record<string, unknown>;
  }> = [];
  /** The tab whose frame 0 runs the content script. */
  contentTab = 7;
  /** Popup windows the extension opened, and the one tab each holds. */
  readonly windows: Array<{ id: number; tabId: number; url: string; open: boolean }> = [];
  /** Called when the extension opens a window, as the page in it loads. */
  onWindowOpened: (opened: { id: number; tabId: number; url: string }) => void = () => undefined;
  private nextWindowId = 500;

  private windowClosed = new Map<number, () => void>();

  /** Run `callback` when the window closes. */
  whenWindowCloses(windowId: number, callback: () => void): void {
    this.windowClosed.set(windowId, callback);
  }

  /** Close a tab, as the user does. */
  closeTab(tabId: number): void {
    if (this.worker.alive) for (const listener of this.worker.tabRemoved) listener(tabId);
  }

  /** Close a window, as the user does. */
  closeWindow(windowId: number): void {
    const found = this.windows.find((window) => window.id === windowId && window.open);
    if (!found) return;
    found.open = false;
    this.windowClosed.get(windowId)?.();
    this.windowClosed.delete(windowId);
    if (this.worker.alive) for (const listener of this.worker.windowRemoved) listener(windowId);
  }
  /** The sender a content-script message carries; follows the page URL. */
  contentSender: () => MessageSender = () => ({ id: EXTENSION_ID });

  readonly local = new FakeStorageArea('local', this);
  readonly sessionArea = new FakeStorageArea('session', this);
  readonly alarmsCreated = new Map<string, unknown>();
  private alarmListeners: Array<(alarm: { name: string }) => void> = [];

  readonly api = this.buildApi();

  async checkFault(
    area: AreaName,
    op: StorageOp,
    keys: string[],
    items?: StorageData
  ): Promise<void> {
    const index = this.faults.findIndex(
      (fault) =>
        (fault.area ?? 'local') === area &&
        fault.op === op &&
        (fault.times === undefined || fault.times > 0) &&
        (!fault.match || fault.match(keys, items))
    );
    if (index < 0) return;
    const fault = this.faults[index];
    if (fault.times !== undefined) fault.times -= 1;
    if (fault.hang) await new Promise(() => undefined);
    throw fault.error ?? new Error(`Injected ${area}.${op} failure`);
  }

  emitChange(changes: Record<string, unknown>, areaName: string): void {
    if (Object.keys(changes).length === 0) return;
    for (const listener of this.changeListeners) listener(clone(changes), areaName);
  }

  /** Run `load` with every onMessage listener it adds attributed to a new worker. */
  private generation(): WorkerGeneration {
    return { listeners: [], windowRemoved: [], tabRemoved: [], alive: true, pending: new Set() };
  }

  startWorker(load: () => void): void {
    this.worker = this.generation();
    this.loadingWorker = true;
    try {
      load();
    } finally {
      this.loadingWorker = false;
    }
  }

  /**
   * Terminate the current worker: it stops receiving messages and every
   * message it has not answered fails the way Chrome fails it.
   */
  killWorker(): void {
    this.worker.alive = false;
    for (const reject of this.worker.pending) reject(new Error(PORT_CLOSED));
    this.worker.pending.clear();
  }

  get workerAlive(): boolean {
    return this.worker.alive && this.worker.listeners.length > 0;
  }

  /** Messages the current worker has received but not answered yet. */
  get pendingMessages(): number {
    return this.worker.pending.size;
  }

  fireAlarm(name: string): void {
    for (const listener of this.alarmListeners) listener({ name });
  }

  /** Deliver a message to the background as `sender`, with Chrome's JSON hop both ways. */
  deliver(message: unknown, sender: MessageSender): Promise<unknown> {
    const worker = this.worker;
    if (!worker.alive || worker.listeners.length === 0) {
      return Promise.reject(new Error(NO_RECEIVER));
    }
    const json = clone(message) as Record<string, unknown>;
    this.sentToBackground.push({ message: json, sender });
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (error: Error) => {
        if (settled) return;
        settled = true;
        reject(error);
      };
      worker.pending.add(fail);
      const sendResponse = (response?: unknown) => {
        if (settled || !worker.alive) return;
        settled = true;
        worker.pending.delete(fail);
        resolve(clone(response));
      };
      let keepOpen = false;
      for (const listener of worker.listeners) {
        if (listener(json, clone(sender), sendResponse) === true) keepOpen = true;
      }
      if (!keepOpen && !settled) {
        worker.pending.delete(fail);
        fail(new Error(PORT_CLOSED));
      }
    });
  }

  private buildApi() {
    const self = this;
    const onMessage = {
      addListener(listener: MessageListener) {
        if (self.loadingWorker) self.worker.listeners.push(listener);
        else self.contentListeners.push(listener);
      },
      removeListener(listener: MessageListener) {
        self.worker.listeners = self.worker.listeners.filter((l) => l !== listener);
        self.contentListeners = self.contentListeners.filter((l) => l !== listener);
      },
      hasListeners: () => self.worker.listeners.length > 0,
    };
    const lifecycle = () => ({ addListener: () => undefined, removeListener: () => undefined });
    return {
      runtime: {
        id: EXTENSION_ID,
        lastError: undefined,
        getURL: (path: string) => `${EXTENSION_ORIGIN}/${path.replace(/^\//, '')}`,
        getManifest: () => ({
          manifest_version: 3,
          version: '0.0.0-test',
          permissions: ['storage', 'alarms', 'favicon'],
          web_accessible_resources: [
            { resources: ['vault-dialog.html'], matches: ['https://*/*'], use_dynamic_url: true },
          ],
        }),
        sendMessage: (message: unknown) => self.deliver(message, self.contentSender()),
        onMessage,
        onInstalled: lifecycle(),
        onStartup: lifecycle(),
        onSuspend: lifecycle(),
      },
      storage: {
        local: this.local,
        session: this.sessionArea,
        onChanged: {
          addListener: (listener: ChangeListener) => self.changeListeners.push(listener),
          removeListener: (listener: ChangeListener) => {
            self.changeListeners = self.changeListeners.filter((l) => l !== listener);
          },
        },
      },
      alarms: {
        create: (name: string, info: unknown) => {
          self.alarmsCreated.set(name, info);
        },
        clear: async (name: string) => self.alarmsCreated.delete(name),
        get: async (name: string) =>
          self.alarmsCreated.has(name)
            ? { name, ...(self.alarmsCreated.get(name) as object) }
            : undefined,
        onAlarm: {
          addListener: (listener: (alarm: { name: string }) => void) =>
            self.alarmListeners.push(listener),
        },
      },
      windows: {
        create: async (options: { url: string }) => {
          // A relative URL is the extension's own, as in Chrome.
          const url = new URL(options.url, `${EXTENSION_ORIGIN}/`).href;
          const opened = { id: self.nextWindowId++, tabId: self.nextWindowId++, url };
          self.windows.push({ ...opened, open: true });
          setTimeout(() => self.onWindowOpened(opened), 0);
          return { id: opened.id, tabs: [{ id: opened.tabId }] };
        },
        remove: async (windowId: number) => self.closeWindow(windowId),
        get: async (windowId: number) => ({ id: windowId, left: 0, top: 0, width: 1280 }),
        onRemoved: {
          addListener: (listener: (windowId: number) => void) => {
            if (self.loadingWorker) self.worker.windowRemoved.push(listener);
          },
        },
      },
      tabs: {
        get: async (tabId: number) => ({ id: tabId, windowId: 1 }),
        onRemoved: {
          addListener: (listener: (tabId: number) => void) => {
            if (self.loadingWorker) self.worker.tabRemoved.push(listener);
          },
        },
        /**
         * To the page's content script, which runs in frame 0 of tab
         * `contentTab`; any other tab or frame has no receiver.
         */
        sendMessage: (tabId: number, message: unknown, options?: { frameId?: number }) => {
          const frameId = options?.frameId;
          self.sentToTabs.push({ tabId, frameId, message: clone(message) as any });
          if (
            tabId !== self.contentTab ||
            (frameId !== undefined && frameId !== 0) ||
            self.contentListeners.length === 0
          ) {
            return Promise.reject(new Error(NO_RECEIVER));
          }
          return new Promise((resolve) => {
            let settled = false;
            const sendResponse = (response?: unknown) => {
              if (settled) return;
              settled = true;
              resolve(clone(response));
            };
            let keepOpen = false;
            for (const listener of [...self.contentListeners]) {
              if (listener(clone(message), { id: EXTENSION_ID }, sendResponse) === true) {
                keepOpen = true;
              }
            }
            if (!keepOpen) sendResponse(undefined);
          });
        },
      },
    };
  }

  /** Replace the global `chrome` with this fake. */
  install(): void {
    // tests/setup.ts defines it writable but not configurable.
    (globalThis as Record<string, unknown>).chrome = this.api;
  }
}
