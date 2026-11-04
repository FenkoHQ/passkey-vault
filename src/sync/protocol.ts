export const NOSTR_EVENT_KIND = 30078;
export const SYNC_BUNDLE_VERSION = '4.0';
export const SYNC_SEND_INTERVAL_MS = 10000;
export const SYNC_HEARTBEAT_MS = 300000;
export const SYNC_RECONNECT_MS = 5000;
export const SYNC_LOOKBACK_SECONDS = 3600;
export const MAX_SYNC_EVENTS = 1000;

export const SYNC_KEY_PREFIX = 'pkvault-sync-v5';
export const SYNC_EVENT_PREFIX = 'pksync-v5';

// Protocol v4, whose chain ID was a prefix of SHA-256 of the phrase. Only the
// one-time cleanup of a migrated device's old relay events still uses them.
export const LEGACY_SYNC_KEY_PREFIX = 'pkvault-sync-v4';
export const LEGACY_SYNC_EVENT_PREFIX = 'pksync-v4';
/** Storage key of a migrated device's pending v4 cleanup (legacy-chain.ts). */
export const LEGACY_CLEANUP_KEY = 'sync_legacy_cleanup';
