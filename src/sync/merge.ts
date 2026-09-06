export const SYNC_DELETIONS_KEY = 'sync_deletions';

export interface SyncDeletion {
  kind: 'passkey' | 'totp';
  id: string;
  deletedAt: number;
}

interface SyncRecord {
  id: string;
  createdAt: number;
  updatedAt?: number;
  counter?: number;
}

export function restoreRecord<T extends SyncRecord>(
  record: T,
  deletions: SyncDeletion[],
  kind: SyncDeletion['kind']
): T {
  let updatedAt = Math.max(Date.now(), (record.updatedAt ?? record.createdAt) + 1);
  for (const deletion of deletions) {
    if (deletion.kind === kind && deletion.id === record.id) {
      updatedAt = Math.max(updatedAt, deletion.deletedAt + 1);
    }
  }
  return { ...record, updatedAt };
}

export function mergeDeletions(local: SyncDeletion[], remote: SyncDeletion[]): SyncDeletion[] {
  const entries = new Map<string, SyncDeletion>();
  for (const item of [...local, ...remote]) {
    if (
      !item ||
      !['passkey', 'totp'].includes(item.kind) ||
      typeof item.id !== 'string' ||
      !Number.isFinite(item.deletedAt)
    ) {
      continue;
    }
    const key = `${item.kind}:${item.id}`;
    if (item.deletedAt > (entries.get(key)?.deletedAt ?? -Infinity)) {
      entries.set(key, item);
    }
  }
  // Keep deletion records: an offline peer can return after any length of time.
  return [...entries.values()];
}

// ASCII encoding gives JS, Java and Swift the same ordering, including Unicode
// keys and fractional numbers. Counters merge separately from record revisions.
function canonical(value: unknown): string {
  if (value === null || value === undefined) {
    return 'n';
  }
  if (typeof value === 'boolean') {
    return value ? 'b1' : 'b0';
  }
  if (typeof value === 'number') {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setFloat64(0, value === 0 ? 0 : value);
    return 'd' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }
  if (typeof value === 'string') {
    let encoded = 's';
    for (let i = 0; i < value.length; i++) {
      encoded += value.charCodeAt(i).toString(16).padStart(4, '0');
    }
    return encoded + ';';
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonical).join('') + ']';
  }
  const object = value as Record<string, unknown>;
  return (
    '{' +
    Object.keys(object)
      .sort()
      .filter((key) => object[key] !== undefined)
      .map((key) => canonical(key) + canonical(object[key]))
      .join('') +
    '}'
  );
}

function recordOrder(record: SyncRecord): string {
  const value = { ...record } as Record<string, unknown>;
  delete value.counter;
  delete value.syncSource;
  delete value.syncTimestamp;
  return canonical(value);
}

export function mergeRecords<T extends SyncRecord>(
  local: T[],
  remote: T[],
  deletions: SyncDeletion[],
  kind: SyncDeletion['kind']
): T[] {
  const records = new Map(local.map((item) => [item.id, item]));
  for (const incoming of remote) {
    const current = records.get(incoming.id);
    if (!current) {
      records.set(incoming.id, incoming);
      continue;
    }
    const currentTime = current.updatedAt ?? current.createdAt;
    const incomingTime = incoming.updatedAt ?? incoming.createdAt;
    // Equal timestamps resolve deterministically, regardless of delivery order.
    const newer =
      incomingTime > currentTime ||
      (incomingTime === currentTime && recordOrder(incoming) > recordOrder(current));
    records.set(incoming.id, {
      ...(newer ? incoming : current),
      counter: Math.max(current.counter || 0, incoming.counter || 0),
    });
  }
  for (const deletion of deletions) {
    if (deletion.kind !== kind) {
      continue;
    }
    const record = records.get(deletion.id);
    if (record && (record.updatedAt ?? record.createdAt) <= deletion.deletedAt) {
      records.delete(deletion.id);
    }
  }
  return [...records.values()];
}
