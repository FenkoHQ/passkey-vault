jest.mock('../src/crypto/secure-storage', () => ({
  secureStorage: {
    isStorageUnlocked: () => false,
    isSetup: async () => false,
  },
}));

import {
  issueHotpCode,
  loadTotpEntries,
  saveTotpEntries,
  TOTP_STORAGE_KEY,
  type StoredTotpEntry,
} from '../src/crypto/totp-store';
import { mergeRecords } from '../src/sync/merge';

// RFC 4226 Appendix D secret, as base64.
const RFC_SECRET_B64 = Buffer.from('12345678901234567890').toString('base64');

function hotpEntry(overrides: Partial<StoredTotpEntry> = {}): StoredTotpEntry {
  return {
    id: 'hotp-1',
    type: 'hotp',
    issuer: 'Acme',
    account: 'bob',
    secretB64: RFC_SECRET_B64,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    counter: 0,
    createdAt: 1000,
    ...overrides,
  };
}

describe('issueHotpCode', () => {
  let store: Record<string, unknown>;

  beforeEach(() => {
    store = {};
    const local = chrome.storage.local as unknown as {
      get: jest.Mock;
      set: jest.Mock;
    };
    local.get.mockImplementation(async (key: string) => ({ [key]: store[key] }));
    local.set.mockImplementation(async (items: Record<string, unknown>) => {
      Object.assign(store, items);
    });
  });

  it('issues successive RFC 4226 codes and persists the advanced counter', async () => {
    await saveTotpEntries([hotpEntry()]);

    const first = await issueHotpCode('hotp-1', 5000);
    const second = await issueHotpCode('hotp-1', 6000);
    const third = await issueHotpCode('hotp-1', 7000);

    expect([first?.code, second?.code, third?.code]).toEqual(['755224', '287082', '359152']);
    expect([first?.counter, second?.counter, third?.counter]).toEqual([0, 1, 2]);

    const [stored] = await loadTotpEntries();
    expect(stored.counter).toBe(3);
    expect(stored.lastUsed).toBe(7000);
    expect(third?.entry).toEqual(stored);
  });

  it('starts from an imported counter value', async () => {
    await saveTotpEntries([hotpEntry({ counter: 9 })]);
    const issued = await issueHotpCode('hotp-1');
    // RFC 4226 Appendix D, count 9.
    expect(issued?.code).toBe('520489');
    expect((await loadTotpEntries())[0].counter).toBe(10);
  });

  it('does not bump updatedAt, so the advance syncs by counter without beating a deletion', async () => {
    await saveTotpEntries([hotpEntry({ updatedAt: 2000 } as Partial<StoredTotpEntry>)]);
    const issued = await issueHotpCode('hotp-1', 9000);
    const advanced = issued!.entry as StoredTotpEntry & { updatedAt?: number };
    expect(advanced.updatedAt).toBe(2000);

    // A peer still holding counter 0 takes the higher counter on merge.
    const merged = mergeRecords([hotpEntry()], [advanced], [], 'totp');
    expect(merged[0].counter).toBe(1);

    // A deletion made elsewhere after the last edit still removes the entry.
    const deleted = mergeRecords(
      [advanced],
      [],
      [{ kind: 'totp', id: 'hotp-1', deletedAt: 3000 }],
      'totp'
    );
    expect(deleted).toEqual([]);
  });

  it('leaves other entries untouched and returns null for an unknown id', async () => {
    const other = hotpEntry({ id: 'hotp-2', counter: 4 });
    await saveTotpEntries([hotpEntry(), other]);
    expect(await issueHotpCode('missing')).toBeNull();
    await issueHotpCode('hotp-1');
    const entries = (store[TOTP_STORAGE_KEY] as StoredTotpEntry[]).map((e) => [e.id, e.counter]);
    expect(entries).toEqual([
      ['hotp-1', 1],
      ['hotp-2', 4],
    ]);
  });

  it('refuses to consume a counter on a TOTP entry', async () => {
    await saveTotpEntries([hotpEntry({ type: 'totp' })]);
    await expect(issueHotpCode('hotp-1')).rejects.toThrow('Not an HOTP entry');
    expect((await loadTotpEntries())[0].counter).toBe(0);
  });
});
