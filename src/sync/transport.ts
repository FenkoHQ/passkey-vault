import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { SYNC_SEND_INTERVAL_MS, SYNC_BUNDLE_VERSION } from './protocol';

// Leave room for signatures, tags and JSON within a 16 KiB relay message.
export const MAX_EVENT_BYTES = 16384;
const CHUNK_BYTES = 12000;
const MAX_CHUNKS = 1400;
const MAX_ASSEMBLIES = 4;
const ASSEMBLY_TTL_MS = 30 * 60 * 1000;
export const MAX_SEND_ATTEMPTS = 5;
const MAX_RETRY_MS = 2 * 60 * 1000;

interface Chunk {
  version: typeof SYNC_BUNDLE_VERSION;
  digest: string;
  index: number;
  total: number;
  data: string;
}

function digest(content: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(content)));
}

export function splitMessage(content: string): string[] {
  if (content.length <= CHUNK_BYTES) {
    return [content];
  }
  const total = Math.ceil(content.length / CHUNK_BYTES);
  if (total > MAX_CHUNKS) {
    throw new Error('Vault exceeds sync capacity. Export a backup before reducing it.');
  }
  const hash = digest(content);
  return Array.from({ length: total }, (_, index) =>
    JSON.stringify({
      version: SYNC_BUNDLE_VERSION,
      digest: hash,
      index,
      total,
      data: content.slice(index * CHUNK_BYTES, (index + 1) * CHUNK_BYTES),
    } satisfies Chunk)
  );
}

export class ChunkCollector {
  private requested = new Set<string>();
  private assemblies = new Map<
    string,
    { parts: Map<number, string>; total: number; time: number }
  >();

  accept(content: string): string | null {
    const chunk = JSON.parse(content) as Chunk;
    if (!('digest' in chunk)) {
      return content;
    }
    if (
      chunk.version !== SYNC_BUNDLE_VERSION ||
      !/^[a-f0-9]{64}$/.test(chunk.digest) ||
      !Number.isInteger(chunk.total) ||
      chunk.total < 1 ||
      chunk.total > MAX_CHUNKS ||
      !Number.isInteger(chunk.index) ||
      chunk.index < 0 ||
      chunk.index >= chunk.total ||
      typeof chunk.data !== 'string' ||
      chunk.data.length > CHUNK_BYTES
    ) {
      throw new Error('Invalid sync chunk');
    }
    for (const [id, item] of this.assemblies) {
      if (Date.now() - item.time > ASSEMBLY_TTL_MS) {
        this.assemblies.delete(id);
        this.requested.delete(id);
      }
    }
    let assembly = this.assemblies.get(chunk.digest);
    if (!assembly) {
      if (this.assemblies.size >= MAX_ASSEMBLIES) {
        const oldest = this.assemblies.keys().next().value!;
        this.assemblies.delete(oldest);
        this.requested.delete(oldest);
      }
      assembly = { parts: new Map(), total: chunk.total, time: Date.now() };
      this.assemblies.set(chunk.digest, assembly);
    }
    if (assembly.total !== chunk.total) {
      throw new Error('Conflicting sync chunks');
    }
    assembly.parts.set(chunk.index, chunk.data);
    if (assembly.parts.size !== chunk.total) {
      return null;
    }
    const joined = Array.from({ length: chunk.total }, (_, i) => assembly!.parts.get(i)!).join('');
    if (digest(joined) !== chunk.digest) {
      throw new Error('Corrupt sync snapshot');
    }
    // Keep completed parts briefly so a failed storage write can retry the last event.
    return joined;
  }

  missing(content: string, address: string, author: string): string[] {
    const chunk = JSON.parse(content) as Chunk;
    const assembly = this.assemblies.get(chunk.digest);
    if (!assembly || this.requested.has(chunk.digest)) {
      return [];
    }
    this.requested.add(chunk.digest);
    const base = address.replace(/-\d+$/, '');
    const addresses = Array.from({ length: chunk.total }, (_, i) => `${base}-${i}`);
    const pageSize = 50;
    const requests = [];
    // Explicit addresses avoid relying on a relay's default history limit.
    for (let offset = 0; offset < addresses.length; offset += pageSize) {
      requests.push(
        JSON.stringify([
          'REQ',
          `parts_${chunk.digest}_${offset}`,
          {
            authors: [author],
            '#d': addresses.slice(offset, offset + pageSize),
            limit: pageSize,
          },
        ])
      );
    }
    return requests;
  }

  clear(): void {
    this.assemblies.clear();
    this.requested.clear();
  }
}

export interface SignedFrame {
  id: string;
}

// An attempt resends identical signed events. Delayed ACKs remain meaningful.
export class Delivery<T extends SignedFrame> {
  private attempts = 0;
  private nextAttempt = 0;
  private accepted = new Set<string>();

  constructor(private frames: T[]) {}

  get complete(): boolean {
    return this.accepted.size === this.frames.length;
  }
  get exhausted(): boolean {
    return this.attempts >= MAX_SEND_ATTEMPTS && Date.now() >= this.nextAttempt;
  }
  get delay(): number {
    return Math.max(0, this.nextAttempt - Date.now());
  }

  acknowledge(id: string): boolean {
    if (!this.frames.some((frame) => frame.id === id)) {
      return false;
    }
    this.accepted.add(id);
    return true;
  }

  take(): T[] {
    if (this.complete || this.exhausted || this.delay > 0) {
      return [];
    }
    this.nextAttempt =
      Date.now() + Math.min(SYNC_SEND_INTERVAL_MS * 2 ** this.attempts, MAX_RETRY_MS);
    this.attempts++;
    return this.frames.filter((frame) => !this.accepted.has(frame.id));
  }

  retry(): void {
    this.attempts = 0;
    this.nextAttempt = 0;
  }
}
