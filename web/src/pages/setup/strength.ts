export type Strength = 'tooShort' | 'fair' | 'good' | 'strong';

export const MIN_PASSPHRASE_LENGTH = 16;

// passphraseStrength is a simple, local estimate for the strength meter. The server rates the
// passphrase with the same rule (internal/setup/strength.go, PassphraseStrength), code point for
// code point, and refuses anything below good; internal/setup/testdata/strength.json drives both tests:
//   - the length is the number of code points ([...p].length); below 16 is tooShort;
//   - the classes are [a-z], [A-Z], [0-9] and "other" (/[^A-Za-z0-9\s]/), counted on p as typed;
//   - the words are p.trim().split(/\s+/) without empty pieces; distinct is the number of different words;
//   - word cycle: if the words are one shorter list repeated (the smallest period p ≤ len/2 that divides
//     the count), only the first p words are kept; the core is the kept words joined by one space;
//   - rune period: if the core is one shorter run of code points repeated (the smallest period q ≤ n/2
//     that divides the code point count n), only its first q code points are kept;
//   - a run of 3 or more identical code points becomes one (a double stays);
//   - a run of 3 or more code points that each step +1, or each step -1 (abc, 123, zyx), becomes its
//     first 2; runs are taken greedily from the left, each as long as it goes;
//   - effective is the code point count of the result; below 16 is fair; otherwise
//     score = (effective ≥ 20) + (effective ≥ 28) + (classes ≥ 3 or distinct ≥ 4): 2 or more strong,
//     1 good, 0 fair.
export function passphraseStrength(p: string): Strength {
  if ([...p].length < MIN_PASSPHRASE_LENGTH) return 'tooShort';
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9\s]/].filter((re) => re.test(p)).length;
  let words = p
    .trim()
    .split(/\s+/)
    .filter((w) => w !== '');
  const distinct = new Set(words).size;
  const wordPeriod = period(words);
  if (wordPeriod > 0) words = words.slice(0, wordPeriod);
  let core = [...words.join(' ')].map((c) => c.codePointAt(0) ?? 0);
  const runePeriod = period(core);
  if (runePeriod > 0) core = core.slice(0, runePeriod);
  const effective = collapseSequences(collapseRuns(core)).length;
  if (effective < MIN_PASSPHRASE_LENGTH) return 'fair';
  const score = Number(effective >= 20) + Number(effective >= 28) + Number(classes >= 3 || distinct >= 4);
  if (score >= 2) return 'strong';
  return score === 1 ? 'good' : 'fair';
}

// period returns the smallest k with 1 ≤ k ≤ n/2 and n % k === 0 such that item i equals item i % k
// for every i, or 0 when there is none.
function period<T>(items: readonly T[]): number {
  const n = items.length;
  for (let k = 1; k <= n / 2; k++) {
    if (n % k === 0 && items.every((item, i) => item === items[i % k])) return k;
  }
  return 0;
}

// collapseRuns turns every run of 3 or more identical code points into one.
function collapseRuns(cps: readonly number[]): number[] {
  const out: number[] = [];
  for (let i = 0; i < cps.length; ) {
    let j = i + 1;
    while (j < cps.length && cps[j] === cps[i]) j++;
    if (j - i >= 3) out.push(cps[i]);
    else out.push(...cps.slice(i, j));
    i = j;
  }
  return out;
}

// collapseSequences turns every run of 3 or more code points that each step +1 (or each step -1) into
// its first 2, taking the runs greedily from the left, each as long as it goes.
function collapseSequences(cps: readonly number[]): number[] {
  const out: number[] = [];
  for (let i = 0; i < cps.length; ) {
    let j = i + 1;
    const step = j < cps.length ? cps[j] - cps[i] : 0;
    if (step === 1 || step === -1) {
      while (j + 1 < cps.length && cps[j + 1] - cps[j] === step) j++;
      j++; // j is now one past the run
    }
    if (j - i >= 3) {
      out.push(cps[i], cps[i + 1]);
      i = j;
    } else {
      out.push(cps[i]); // a sequence may still start at the next code point ("babc")
      i++;
    }
  }
  return out;
}
