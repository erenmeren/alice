import { errorPairsIn, goErrorPairs, readRepoFile, webTestFiles } from './goSources';

// Every error a web test makes the server answer with must exist in the server's error table, so a
// test cannot pass on a code and reason pair that the real API never sends.
describe('error codes used in web tests', () => {
  const table = goErrorPairs();

  it('reads the real error table', () => {
    expect(table.has('ALC-AUTH-0002 auth.forbidden')).toBe(true);
    expect(table.has('ALC-SYS-0008 system.precondition_failed')).toBe(true);
  });

  it('finds the pairs of both call forms', () => {
    expect(errorPairsIn("errorResponse(403, 'ALC-X-0001', 'a.b', {})\nerror: { code: 'ALC-Y-0002', reason: 'c.d' }")).toEqual(['ALC-X-0001 a.b', 'ALC-Y-0002 c.d']);
  });

  it('catches an invented pair in any quote style', () => {
    const invented = [
      'errorResponse(403, "ALC-FAKE-0001", "fake.reason")',
      'errorResponse(403, `ALC-FAKE-0002`, `fake.other`)',
      'error: { code: "ALC-FAKE-0003", reason: "fake.third" }',
    ].join('\n');
    const pairs = errorPairsIn(invented);
    expect(pairs).toEqual(['ALC-FAKE-0001 fake.reason', 'ALC-FAKE-0002 fake.other', 'ALC-FAKE-0003 fake.third']);
    expect(pairs.filter((p) => !table.has(p))).toHaveLength(3);
  });

  it('exist for every pair a test file uses', () => {
    const bad: string[] = [];
    for (const f of webTestFiles()) {
      if (f.endsWith('errorPairs.test.ts')) continue;
      for (const pair of errorPairsIn(readRepoFile(f))) if (!table.has(pair)) bad.push(`${f}: ${pair}`);
    }
    expect(bad).toEqual([]);
  });
});
