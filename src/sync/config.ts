// Old builds persisted a per-device salt that cannot be used for shared keys.
export function cleanSyncConfig<T extends object>(config: T): T {
  const next = { ...config };
  delete (next as Record<string, unknown>).syncSalt;
  return next;
}
