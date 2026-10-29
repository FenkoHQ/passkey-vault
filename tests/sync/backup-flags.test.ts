import {
  IMPORTED_BACKUP_FLAGS,
  applyBackupRepairs,
  backupFlagsOf,
  canRepairBackupFlags,
  carryBackupFields,
  stampLegacyBackupFlags,
  withBackupFlags,
  type BackupFields,
} from '../../src/sync/backup-flags';
import { mergeRecords } from '../../src/sync/merge';

const OFF = { backupEligible: false, backupState: false };
const ON = { backupEligible: true, backupState: true };

interface TestRecord extends BackupFields {
  id: string;
  rpId: string;
  publicKey: string;
  createdAt: number;
  updatedAt?: number;
  counter: number;
  label?: string;
}

function record(extra: Partial<TestRecord> = {}): TestRecord {
  return {
    id: 'cred',
    rpId: 'tele.example.com',
    publicKey: 'pub',
    createdAt: 1,
    counter: 0,
    ...extra,
  };
}

describe('backupFlagsOf', () => {
  it("signs with the passkey's own flags", () => {
    expect(backupFlagsOf(record(ON), OFF)).toEqual(ON);
    expect(backupFlagsOf(record(OFF), ON)).toEqual(OFF);
  });

  it('falls back only when the passkey has no flags of its own', () => {
    expect(backupFlagsOf(record(), ON)).toEqual(ON);
    expect(backupFlagsOf(record(), OFF)).toEqual(OFF);
  });

  it('never produces backed up without backup eligible', () => {
    expect(backupFlagsOf(record({ backupEligible: false, backupState: true }), ON)).toEqual(OFF);
    expect(backupFlagsOf(record(), { backupEligible: false, backupState: true })).toEqual(OFF);
  });
});

describe('stampLegacyBackupFlags', () => {
  it('records the pre-upgrade flags on passkeys that have none, and nothing else', () => {
    const imported = withBackupFlags(record({ id: 'new' }), ON, 'imported');
    const { records, stamped } = stampLegacyBackupFlags([record(), imported], ON);

    expect(stamped).toBe(1);
    expect(records[0]).toMatchObject({ ...ON, backupSource: 'legacy' });
    expect(records[1]).toBe(imported);
  });

  it('does not bump the revision, so it never outranks a real edit', () => {
    const { records } = stampLegacyBackupFlags([record({ updatedAt: 7 })], OFF);
    expect(records[0].updatedAt).toBe(7);
  });

  it('is idempotent', () => {
    const once = stampLegacyBackupFlags([record()], ON).records;
    expect(stampLegacyBackupFlags(once, OFF)).toEqual({ records: once, stamped: 0 });
  });
});

describe('canRepairBackupFlags', () => {
  it('lets a re-import correct assumptions but not facts or the user', () => {
    expect(canRepairBackupFlags(record())).toBe(true);
    expect(canRepairBackupFlags(withBackupFlags(record(), OFF, 'legacy'))).toBe(true);
    expect(canRepairBackupFlags(withBackupFlags(record(), OFF, 'imported'))).toBe(true);
    expect(canRepairBackupFlags(withBackupFlags(record(), OFF, 'created'))).toBe(false);
    expect(canRepairBackupFlags(withBackupFlags(record(), OFF, 'manual'))).toBe(false);
  });
});

describe('applyBackupRepairs', () => {
  const repair = { id: 'cred', rpId: 'tele.example.com', publicKey: 'pub', ...ON };

  it('fixes a legacy passkey imported before flags existed', () => {
    const legacy = withBackupFlags(record({ counter: 9, updatedAt: 50 }), OFF, 'legacy');
    const { records, repaired } = applyBackupRepairs([legacy], [repair], 100);

    expect(repaired).toBe(1);
    expect(records[0]).toMatchObject({ ...ON, backupSource: 'imported', updatedAt: 100 });
    // Only the backup fields move: counters, keys and names stay as stored.
    expect(records[0].counter).toBe(9);
  });

  it('moves the revision past the stored one so the fix wins a sync merge', () => {
    const legacy = withBackupFlags(record({ updatedAt: 500 }), OFF, 'legacy');
    expect(applyBackupRepairs([legacy], [repair], 100).records[0].updatedAt).toBe(501);
  });

  it('refuses a repair whose RP or key does not match the stored credential', () => {
    const legacy = withBackupFlags(record(), OFF, 'legacy');
    for (const wrong of [
      { ...repair, rpId: 'evil.example.com' },
      { ...repair, publicKey: 'other' },
    ]) {
      expect(applyBackupRepairs([legacy], [wrong]).repaired).toBe(0);
    }
  });

  it('leaves passkeys the vault created or the user set', () => {
    for (const source of ['created', 'manual'] as const) {
      const kept = withBackupFlags(record(), OFF, source);
      expect(applyBackupRepairs([kept], [repair]).records[0]).toBe(kept);
    }
  });

  it('does not count a repair that changes nothing', () => {
    const already = withBackupFlags(record(), ON, 'legacy');
    expect(applyBackupRepairs([already], [repair])).toEqual({ records: [already], repaired: 0 });
  });
});

describe('carrying flags through a sync merge', () => {
  it('keeps flags when the winning copy predates them', () => {
    const flagged = withBackupFlags(record({ label: 'old' }), ON, 'imported');
    const stale = record({ label: 'renamed', updatedAt: 9 });

    expect(carryBackupFields(stale, flagged)).toMatchObject({ label: 'renamed', ...ON });
    expect(mergeRecords([flagged], [stale], [], 'passkey')[0]).toMatchObject({
      label: 'renamed',
      ...ON,
      backupSource: 'imported',
    });
    expect(mergeRecords([stale], [flagged], [], 'passkey')[0]).toMatchObject(ON);
  });

  it('keeps an explicit device-bound choice instead of treating it as missing', () => {
    const flagged = withBackupFlags(record(), ON, 'imported');
    const manual = withBackupFlags(record({ updatedAt: 9 }), OFF, 'manual');

    expect(mergeRecords([flagged], [manual], [], 'passkey')[0]).toMatchObject({
      ...OFF,
      backupSource: 'manual',
    });
  });

  it('matches what syncing managers assert for imports', () => {
    expect(IMPORTED_BACKUP_FLAGS).toEqual(ON);
  });
});
