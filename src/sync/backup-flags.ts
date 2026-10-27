/**
 * Per-credential WebAuthn backup flags.
 *
 * BE (backup eligible) is fixed when a credential is created: WebAuthn L3
 * §6.1.3 says it must not change, and relying parties built on go-webauthn
 * (Teleport, among others) store it and reject any later assertion that
 * disagrees. So the flags travel with each passkey record, synced to every
 * device, instead of coming from a vault-wide setting at sign-in.
 *
 * `backupSource` says where a record's flags came from. It drives wording in
 * the UI and decides what a re-import may overwrite; it never changes the
 * bytes signed.
 */

export type BackupSource = 'created' | 'imported' | 'legacy' | 'manual';

export interface BackupFlags {
  backupEligible: boolean;
  backupState: boolean;
}

export interface BackupFields {
  backupEligible?: boolean;
  backupState?: boolean;
  backupSource?: BackupSource;
}

/**
 * What passkeys exported from another manager assert. Bitwarden, 1Password,
 * iCloud Keychain and Google Password Manager all sync their passkeys and
 * report BE=1, BS=1, and none of their export formats record the flags.
 */
export const IMPORTED_BACKUP_FLAGS: BackupFlags = { backupEligible: true, backupState: true };

/** What every build before per-credential flags asserted unless told otherwise. */
export const PRE_UPGRADE_BACKUP_FLAGS: BackupFlags = { backupEligible: false, backupState: false };

const SOURCES: readonly BackupSource[] = ['created', 'imported', 'legacy', 'manual'];

/** BS without BE is invalid (WebAuthn L3 §6.1), so BE gates BS everywhere. */
export function normalizeBackupFlags(backupEligible: boolean, backupState: boolean): BackupFlags {
  return { backupEligible, backupState: backupEligible && backupState };
}

export function hasBackupFlags(record: BackupFields | null | undefined): boolean {
  return typeof record?.backupEligible === 'boolean';
}

export function backupSourceOf(record: BackupFields | null | undefined): BackupSource | null {
  const source = record?.backupSource;
  return source && SOURCES.includes(source) ? source : null;
}

/** The flags to sign with: the record's own, or `fallback` for a record that has none yet. */
export function backupFlagsOf(
  record: BackupFields | null | undefined,
  fallback: BackupFlags
): BackupFlags {
  if (!hasBackupFlags(record))
    return normalizeBackupFlags(fallback.backupEligible, fallback.backupState);
  return normalizeBackupFlags(record!.backupEligible === true, record!.backupState === true);
}

/** Copy of `record` carrying `flags`, tagged with where they came from. */
export function withBackupFlags<T extends object>(
  record: T,
  flags: BackupFlags,
  source: BackupSource
): T & Required<BackupFields> {
  const normalized = normalizeBackupFlags(flags.backupEligible, flags.backupState);
  return { ...record, ...normalized, backupSource: source };
}

/**
 * Give every record that predates per-credential flags the flags it was
 * already being signed with, so upgrading changes nothing a site sees.
 * Records that already carry flags are left alone. `updatedAt` is not bumped:
 * this records existing behaviour rather than editing the passkey, and the
 * sync merge carries the fields forward whichever copy wins.
 */
export function stampLegacyBackupFlags<T extends BackupFields>(
  records: T[],
  snapshot: BackupFlags
): { records: T[]; stamped: number } {
  let stamped = 0;
  const out = records.map((record) => {
    if (hasBackupFlags(record)) return record;
    stamped += 1;
    return withBackupFlags(record, snapshot, 'legacy') as T;
  });
  return { records: out, stamped };
}

/**
 * Whether a re-import may replace this record's flags with the import's.
 * Flags the vault created or the user set are facts or decisions; flags from
 * an earlier import or the upgrade snapshot are only assumptions.
 */
export function canRepairBackupFlags(record: BackupFields): boolean {
  const source = backupSourceOf(record);
  return !hasBackupFlags(record) || source === null || source === 'imported' || source === 'legacy';
}

/**
 * Sync merges pick a whole winning record. A copy written by a build that
 * predates these fields must not erase them, so when the winner has no flags
 * and the other copy does, the other copy's flags are kept.
 */
export function carryBackupFields<T extends BackupFields>(winner: T, other: T): T {
  if (hasBackupFlags(winner) || !hasBackupFlags(other)) return winner;
  const carried: BackupFields = {
    backupEligible: other.backupEligible,
    backupState: other.backupState === true,
  };
  if (other.backupSource !== undefined) carried.backupSource = other.backupSource;
  return { ...winner, ...carried };
}

/** A re-import's request to correct the flags of a passkey the vault already holds. */
export interface BackupRepair extends BackupFlags {
  id: string;
  rpId: string;
  /** Derived from the imported private key, so a repair cannot reach a different credential. */
  publicKey: string;
}

interface RepairableRecord extends BackupFields {
  id: string;
  rpId: string;
  publicKey?: string;
  createdAt: number;
  updatedAt?: number;
}

/**
 * Apply re-import repairs. Only the backup fields change, only on a record
 * whose id, RP and public key all match, and only where canRepairBackupFlags
 * allows it. The revision moves forward so the correction syncs and wins.
 */
export function applyBackupRepairs<T extends RepairableRecord>(
  records: T[],
  repairs: BackupRepair[],
  now: number = Date.now()
): { records: T[]; repaired: number } {
  const byId = new Map(repairs.map((repair) => [repair.id, repair]));
  let repaired = 0;
  const out = records.map((record) => {
    const repair = byId.get(record.id);
    if (
      !repair ||
      record.rpId !== repair.rpId ||
      !record.publicKey ||
      record.publicKey !== repair.publicKey ||
      !canRepairBackupFlags(record)
    ) {
      return record;
    }
    const flags = normalizeBackupFlags(repair.backupEligible === true, repair.backupState === true);
    if (hasBackupFlags(record)) {
      const current = backupFlagsOf(record, flags);
      if (
        current.backupEligible === flags.backupEligible &&
        current.backupState === flags.backupState
      ) {
        return record;
      }
    }
    repaired += 1;
    const updatedAt = Math.max(now, (record.updatedAt ?? record.createdAt) + 1);
    return { ...withBackupFlags(record, flags, 'imported'), updatedAt } as T;
  });
  return { records: out, repaired };
}
