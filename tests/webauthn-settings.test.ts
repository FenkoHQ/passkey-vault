import {
  BACKUP_FLAGS_SNAPSHOT_KEY,
  DEFAULT_WEBAUTHN_FLAGS,
  ensureBackupFlagsSnapshot,
  preUpgradeBackupFlags,
  WEBAUTHN_FLAGS_KEY,
  normalizeWebAuthnFlags,
  loadWebAuthnFlags,
  saveWebAuthnFlags,
  transportsFor,
} from '../src/background/webauthn-settings';

describe('transportsFor', () => {
  it('reports internal transport for the platform attachment', () => {
    expect(transportsFor('platform')).toEqual(['internal']);
  });

  it('does not infer transport support from cross-platform attachment', () => {
    expect(transportsFor('cross-platform')).toEqual([]);
  });
});

describe('normalizeWebAuthnFlags', () => {
  it('falls back to the defaults for missing or junk input', () => {
    expect(normalizeWebAuthnFlags(undefined)).toEqual(DEFAULT_WEBAUTHN_FLAGS);
    expect(normalizeWebAuthnFlags('nonsense')).toEqual(DEFAULT_WEBAUTHN_FLAGS);
    expect(
      normalizeWebAuthnFlags({
        userVerification: 'sometimes',
        signCounter: 42,
        attachment: null,
        aaguid: 'other',
        backupEligible: 'yes',
      })
    ).toEqual(DEFAULT_WEBAUTHN_FLAGS);
  });

  it('defaults to the shipped behaviour, with new passkeys backup eligible', () => {
    expect(DEFAULT_WEBAUTHN_FLAGS).toEqual({
      userVerification: 'always',
      backupEligible: true,
      backupState: false,
      signCounter: 'increment',
      attachment: 'cross-platform',
      aaguid: 'vault',
    });
  });

  it('drops backup state when the credential is not backup eligible', () => {
    const flags = normalizeWebAuthnFlags({ backupEligible: false, backupState: true });

    expect(flags.backupState).toBe(false);
  });

  it('keeps valid overrides', () => {
    const flags = normalizeWebAuthnFlags({
      userVerification: 'never',
      backupEligible: true,
      backupState: true,
      signCounter: 'zero',
      attachment: 'platform',
      aaguid: 'zero',
    });

    expect(flags).toEqual({
      userVerification: 'never',
      backupEligible: true,
      backupState: true,
      signCounter: 'zero',
      attachment: 'platform',
      aaguid: 'zero',
    });
  });
});

describe('storage', () => {
  const storage = chrome.storage.local as unknown as {
    get: jest.Mock;
    set: jest.Mock;
  };

  beforeEach(() => {
    storage.get.mockReset();
    storage.set.mockReset();
    storage.set.mockResolvedValue(undefined);
  });

  it('returns the defaults when nothing is stored', async () => {
    storage.get.mockResolvedValue({});

    await expect(loadWebAuthnFlags()).resolves.toEqual(DEFAULT_WEBAUTHN_FLAGS);
  });

  it('returns the defaults when storage throws', async () => {
    storage.get.mockRejectedValue(new Error('storage unavailable'));

    await expect(loadWebAuthnFlags()).resolves.toEqual(DEFAULT_WEBAUTHN_FLAGS);
  });

  it('normalizes what it reads back', async () => {
    storage.get.mockResolvedValue({
      [WEBAUTHN_FLAGS_KEY]: { userVerification: 'never', signCounter: 'bogus' },
    });

    const flags = await loadWebAuthnFlags();

    expect(flags.userVerification).toBe('never');
    expect(flags.signCounter).toBe('increment');
  });

  it('normalizes before writing, so a ceremony never sees junk', async () => {
    const written = await saveWebAuthnFlags({
      userVerification: 'never',
      backupState: true,
      attachment: 'made-up',
    });

    expect(storage.set).toHaveBeenCalledWith({
      [WEBAUTHN_FLAGS_KEY]: {
        userVerification: 'never',
        backupEligible: true,
        backupState: true,
        signCounter: 'increment',
        attachment: 'cross-platform',
        aaguid: 'vault',
      },
    });
    expect(written.attachment).toBe('cross-platform');
  });
});

describe('pre-upgrade backup flags', () => {
  const storage = chrome.storage.local as unknown as {
    get: jest.Mock;
    set: jest.Mock;
  };

  beforeEach(() => {
    storage.get.mockReset();
    storage.set.mockReset();
    storage.set.mockResolvedValue(undefined);
  });

  it('reads untouched settings as the old all-off defaults, not the new ones', () => {
    expect(preUpgradeBackupFlags(undefined)).toEqual({
      backupEligible: false,
      backupState: false,
    });
    expect(preUpgradeBackupFlags({ userVerification: 'never' })).toEqual({
      backupEligible: false,
      backupState: false,
    });
  });

  it('keeps the toggles a user turned on to make a site work', () => {
    expect(preUpgradeBackupFlags({ backupEligible: true, backupState: true })).toEqual({
      backupEligible: true,
      backupState: true,
    });
    expect(preUpgradeBackupFlags({ backupEligible: false, backupState: true })).toEqual({
      backupEligible: false,
      backupState: false,
    });
  });

  it('snapshots the stored toggles once', async () => {
    storage.get.mockImplementation(async (keys: string[]) =>
      keys.includes(WEBAUTHN_FLAGS_KEY)
        ? { [WEBAUTHN_FLAGS_KEY]: { backupEligible: true, backupState: true } }
        : {}
    );

    await expect(ensureBackupFlagsSnapshot()).resolves.toEqual({
      backupEligible: true,
      backupState: true,
    });
    expect(storage.set).toHaveBeenCalledWith({
      [BACKUP_FLAGS_SNAPSHOT_KEY]: { backupEligible: true, backupState: true },
    });
  });

  it('never retakes an existing snapshot', async () => {
    storage.get.mockResolvedValue({
      [BACKUP_FLAGS_SNAPSHOT_KEY]: { backupEligible: false, backupState: false },
      [WEBAUTHN_FLAGS_KEY]: { backupEligible: true, backupState: true },
    });

    await expect(ensureBackupFlagsSnapshot()).resolves.toEqual({
      backupEligible: false,
      backupState: false,
    });
    expect(storage.set).not.toHaveBeenCalled();
  });
});
