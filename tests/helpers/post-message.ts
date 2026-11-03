/**
 * window.postMessage as a browser implements it, for the page <-> content
 * script hop.
 *
 * jsdom's postMessage leaves `event.source` null, so the vault's
 * `event.source !== window` guard would drop every message. Browsers also
 * structured-clone the data: the receiver never shares objects with the
 * sender, getters run once at send time, functions throw DataCloneError
 * synchronously, and delivery happens on a later task. The page world and
 * the content script's isolated world see the same message events, which is
 * what dispatching on the one jsdom window reproduces.
 */

function dataCloneError(what: string): DOMException {
  return new DOMException(`${what} could not be cloned.`, 'DataCloneError');
}

/** Structured clone (HTML §2.7) for the value types a WebAuthn message can hold. */
export function structuredCloneLite(value: unknown, memory = new Map<unknown, unknown>()): unknown {
  if (value === null || value === undefined) return value;
  const type = typeof value;
  if (type === 'string' || type === 'number' || type === 'boolean' || type === 'bigint') {
    return value;
  }
  if (type === 'symbol') throw dataCloneError('Symbol()');
  if (type === 'function') throw dataCloneError(String(value).slice(0, 40));
  if (memory.has(value)) return memory.get(value);

  if (
    value instanceof ArrayBuffer ||
    Object.prototype.toString.call(value) === '[object ArrayBuffer]'
  ) {
    const copy = (value as ArrayBuffer).slice(0);
    const local = new ArrayBuffer(copy.byteLength);
    new Uint8Array(local).set(new Uint8Array(copy));
    memory.set(value, local);
    return local;
  }
  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    const bytes = new Uint8Array(view.byteLength);
    bytes.set(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
    const name = Object.prototype.toString.call(value).slice(8, -1);
    const ctor = (globalThis as Record<string, unknown>)[name] as
      | (new (buffer: ArrayBuffer, offset?: number, length?: number) => ArrayBufferView)
      | undefined;
    let copy: ArrayBufferView;
    if (name === 'DataView') copy = new DataView(bytes.buffer);
    else if (ctor)
      copy = new ctor(
        bytes.buffer,
        0,
        view.byteLength / ((view as Uint8Array).BYTES_PER_ELEMENT || 1)
      );
    else copy = bytes;
    memory.set(value, copy);
    return copy;
  }
  if (value instanceof Date) return new Date(value.getTime());
  if (value instanceof RegExp) return new RegExp(value.source, value.flags);
  if (typeof Node !== 'undefined' && value instanceof Node) throw dataCloneError('Node');
  if (value instanceof Map) {
    const copy = new Map();
    memory.set(value, copy);
    for (const [k, v] of value)
      copy.set(structuredCloneLite(k, memory), structuredCloneLite(v, memory));
    return copy;
  }
  if (value instanceof Set) {
    const copy = new Set();
    memory.set(value, copy);
    for (const v of value) copy.add(structuredCloneLite(v, memory));
    return copy;
  }
  if (Array.isArray(value)) {
    const copy: unknown[] = [];
    memory.set(value, copy);
    value.forEach((item, index) => {
      copy[index] = structuredCloneLite(item, memory);
    });
    return copy;
  }
  if (value instanceof Error || Object.prototype.toString.call(value) === '[object Error]') {
    const error = value as Error;
    const copy = new Error(error.message);
    copy.name = error.name;
    memory.set(value, copy);
    return copy;
  }
  // Any other object, class instances included, becomes a plain object of its
  // own enumerable string-keyed properties; the prototype does not travel.
  const copy: Record<string, unknown> = {};
  memory.set(value, copy);
  for (const key of Object.keys(value as object)) {
    copy[key] = structuredCloneLite((value as Record<string, unknown>)[key], memory);
  }
  return copy;
}

export interface PostedMessage {
  data: unknown;
  at: number;
}

/**
 * Replace window.postMessage. Returns the log of everything posted, in order,
 * so tests can assert on the traffic between the page and the content script.
 */
export function installPostMessage(): PostedMessage[] {
  const log: PostedMessage[] = [];
  const post = function (this: Window, message: unknown) {
    const data = structuredCloneLite(message);
    log.push({ data, at: Date.now() });
    setTimeout(() => {
      window.dispatchEvent(
        new MessageEvent('message', { data, source: window, origin: window.location.origin })
      );
    }, 0);
  };
  Object.defineProperty(window, 'postMessage', { value: post, writable: true, configurable: true });
  return log;
}
