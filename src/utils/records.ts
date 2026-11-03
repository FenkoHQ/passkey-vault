/**
 * The entries of a stored list that are records at all. A null or a bare
 * string can only come from a damaged store, an old backup or a buggy sync
 * peer, and every lookup reads fields off each entry, so a single one broke
 * every lookup in the list: sign-in and registration on every site. Dropped
 * when read, they disappear with the next save.
 */
export function wellFormedRecords<T>(records: T[]): T[] {
  if (!Array.isArray(records)) return records;
  return records.filter(
    (record) => record !== null && typeof record === 'object' && !Array.isArray(record)
  );
}

/** A record sync can merge: it needs an id to match it against ours. */
export function hasStringId(record: unknown): boolean {
  return typeof (record as { id?: unknown }).id === 'string';
}
