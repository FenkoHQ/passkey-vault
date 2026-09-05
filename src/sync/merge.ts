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
      (incomingTime === currentTime && JSON.stringify(incoming) > JSON.stringify(current));
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
