import {
  DEFAULT_WEBAUTHN_FLAGS,
  WEBAUTHN_FLAGS_KEY,
  normalizeWebAuthnFlags,
  loadWebAuthnFlags,
  saveWebAuthnFlags,
} from '../src/background/webauthn-settings';

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

  it('defaults to the behaviour shipped before the setting existed', () => {
    expect(DEFAULT_WEBAUTHN_FLAGS).toEqual({
      userVerification: 'always',
      backupEligible: false,
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
        backupEligible: false,
        backupState: false,
        signCounter: 'increment',
        attachment: 'cross-platform',
        aaguid: 'vault',
      },
    });
    expect(written.attachment).toBe('cross-platform');
  });
});
