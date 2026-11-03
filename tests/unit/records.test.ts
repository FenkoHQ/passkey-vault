import { hasStringId, wellFormedRecords } from '../../src/utils/records';

describe('wellFormedRecords', () => {
  it('keeps objects and drops everything that is not a record', () => {
    const good = { id: 'a' };
    const records = [good, null, undefined, 'x', 7, true, ['nested'], { id: 'b' }] as unknown[];

    expect(wellFormedRecords(records)).toEqual([good, { id: 'b' }]);
  });

  it('returns a non-array unchanged rather than inventing an empty vault', () => {
    const odd = { not: 'a list' } as unknown as unknown[];

    expect(wellFormedRecords(odd)).toBe(odd);
  });
});

describe('hasStringId', () => {
  it.each([
    [{ id: 'a' }, true],
    [{ id: '' }, true],
    [{ id: 1 }, false],
    [{}, false],
  ])('%j -> %s', (record, expected) => {
    expect(hasStringId(record)).toBe(expected);
  });
});
