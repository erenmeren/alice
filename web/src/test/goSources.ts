import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

// Helpers that read the backend's Go sources, so a test can fail when the backend gains an audit
// action or a job type that the SPA has no label for (as enums.test.ts does for openapi.yaml).

const root = resolve(process.cwd(), '..');

// goFiles lists the non-test .go files below a repository directory (recursively).
export function goFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(join(root, dir), { withFileTypes: true })) {
    const rel = join(dir, e.name);
    if (e.isDirectory()) out.push(...goFiles(rel));
    else if (e.name.endsWith('.go') && !e.name.endsWith('_test.go')) out.push(rel);
  }
  return out;
}

export function readRepoFile(rel: string): string {
  return readFileSync(join(root, rel), 'utf8');
}

// Every way the backend writes an audit action as a literal: an audit.Event field (Action: "x"),
// an assignment (ev.Action = "x"), the deployment recorder (appendAudit(ctx, tx, "x", ...)), the
// jobs runner (jobEvent("x", ...), terminate(ctx, c, reason, "x")), an event table
// ({"x", audit.Success, ...}), the auth helpers (s.adminChange, s.adminFailure, s.auditFailure,
// s.recordFailure: the first dotted literal of the call) and a variable named action chosen by an
// assignment (action := "x"; action, result := "x", ...; event, action := "e", "x").
// "license.upload." + RejectReason(err) is expanded by backendAuditActions. An action computed in
// any other way is not found here.
const ACTION_PATTERNS = [
  /\bAction:\s*"([a-z][a-z0-9_.]*)"/g,
  /\.Action\s*=\s*"([a-z][a-z0-9_.]*)"/g,
  /\bappendAudit\([^"\n]*"([a-z][a-z0-9_.]*)"/g,
  /\bjobEvent\("([a-z][a-z0-9_.]*)"/g,
  /\bterminate\([^"\n]*"[^"\n]*",\s*"([a-z][a-z0-9_.]*)"/g,
  /\{"([a-z][a-z0-9_]*\.[a-z0-9_.]+)",\s*audit\.(?:Success|Failure|Denied)\b/g,
  /\bs\.(?:adminChange|adminFailure|auditFailure|recordFailure)\([^"\n]*"([a-z][a-z0-9_]*\.[a-z0-9_.]+)"/g,
  /\baction(?:,\s*\w+)?\s*:?=\s*"([a-z][a-z0-9_]*\.[a-z0-9_.]+)"/g,
  /\b\w+,\s*action\s*:?=\s*"[^"\n]*",\s*"([a-z][a-z0-9_]*\.[a-z0-9_.]+)"/g,
];

// auditActionsIn finds the audit actions written as literals in a Go source. A prefix that is
// completed at run time ("license.upload." + reason) is left out.
export function auditActionsIn(src: string): string[] {
  const found = new Set<string>();
  for (const re of ACTION_PATTERNS) for (const m of src.matchAll(re)) if (!m[1].endsWith('.')) found.add(m[1]);
  return [...found].sort();
}

// rejectReasonsIn finds the values RejectReason returns (internal/license/errors.go): a refused
// license upload is audited as "license.upload." + RejectReason(err).
export function rejectReasonsIn(src: string): string[] {
  const start = src.indexOf('func RejectReason(');
  if (start < 0) return [];
  const body = src.slice(start, src.indexOf('\n}\n', start) + 2);
  return [...new Set([...body.matchAll(/\breturn\s+"([a-z][a-z0-9_]*)"/g)].map((m) => m[1]))].sort();
}

// jobTypesIn finds the job type constants of internal/inventory/jobs.go (JobXxx = "type").
export function jobTypesIn(src: string): string[] {
  return [...src.matchAll(/^\s*Job\w*\s*=\s*"([a-z][a-z0-9_.]*)"/gm)].map((m) => m[1]).sort();
}

// backendAuditActions is every audit action the backend writes (all of internal/ and cmd/).
export function backendAuditActions(): string[] {
  const found = new Set<string>();
  for (const dir of ['internal', 'cmd']) {
    for (const f of goFiles(dir)) for (const a of auditActionsIn(readRepoFile(f))) found.add(a);
  }
  for (const r of rejectReasonsIn(readRepoFile('internal/license/errors.go'))) found.add(`license.upload.${r}`);
  return [...found].sort();
}

// registeredJobTypes finds the literal names passed to Register("name", class) in internal/jobs/types.go
// (the ones written with a constant, Register(inventory.JobX, ...), are the JobXxx constants above).
export function registeredJobTypes(src: string): string[] {
  return [...src.matchAll(/\bRegister\("([a-z][a-z0-9_.]*)"/g)].map((m) => m[1]).sort();
}

export function backendJobTypes(): string[] {
  return [...new Set([...jobTypesIn(readRepoFile('internal/inventory/jobs.go')), ...registeredJobTypes(readRepoFile('internal/jobs/types.go'))])].sort();
}

// goStringConsts finds the string constants of a Go source whose names match nameRe (for example
// /^StepName\w+$/): `Name = "value"` or `Name Type = "value"` on its own line, with any spacing before the equals sign.
export function goStringConsts(src: string, nameRe: RegExp): string[] {
  const found = new Set<string>();
  for (const m of src.matchAll(/^\s*(?:const\s+)?([A-Za-z]\w*)(?:\s+[A-Za-z][\w.]*)?\s*=\s*"([^"\n]*)"/gm)) if (nameRe.test(m[1])) found.add(m[2]);
  return [...found].sort();
}

export const goConsts = (rel: string, nameRe: RegExp): string[] => goStringConsts(readRepoFile(rel), nameRe);

// callArgsIn finds every string literal passed to a call such as warning("x").
export function callArgsIn(src: string, fn: string): string[] {
  return [...src.matchAll(new RegExp(`\\b${fn}\\("([^"\\n]*)"`, 'g'))].map((m) => m[1]).sort();
}

// goErrorPairs reads the API error table (internal/api, ErrorCode{Code: "ALC-X-0001", Reason: "a.b"})
// as "code reason" strings, so a test can check that the pairs it invents really exist.
export function goErrorPairs(): Set<string> {
  const found = new Set<string>();
  for (const f of goFiles('internal/api')) {
    for (const m of readRepoFile(f).matchAll(/Code:\s*"(ALC-[A-Z]+-\d{4})",\s*Reason:\s*"([a-z][a-z0-9_.]*)"/g)) found.add(`${m[1]} ${m[2]}`);
  }
  return found;
}

// errorPairsIn finds the (code, reason) pairs a test writes: errorResponse(status, 'code', 'reason', ...)
// and object literals {code: 'code', reason: 'reason'}.
// A line that says `not in the error table` is skipped: it deliberately sends what a newer server
// might (a reason this version has no text for).
export function errorPairsIn(source: string): string[] {
  const src = source
    .split('\n')
    .filter((l) => !l.includes('not in the error table'))
    .join('\n');
  const out: string[] = [];
  for (const m of src.matchAll(/errorResponse\(\s*\d+,\s*(['"`])(ALC-[A-Z]+-\d{4})\1,\s*(['"`])([a-z][a-z0-9_.]*)\3/g)) out.push(`${m[2]} ${m[4]}`);
  for (const m of src.matchAll(/code:\s*(['"`])(ALC-[A-Z]+-\d{4})\1,\s*reason:\s*(['"`])([a-z][a-z0-9_.]*)\3/g)) out.push(`${m[2]} ${m[4]}`);
  return out;
}

// webTestFiles lists the test files under web/src (the working directory is web/).
export function webTestFiles(dir = 'web/src'): string[] {
  const out: string[] = [];
  for (const e of readdirSync(join(root, dir), { withFileTypes: true })) {
    const rel = join(dir, e.name);
    if (e.isDirectory()) out.push(...webTestFiles(rel));
    else if (/\.test\.tsx?$/.test(e.name)) out.push(rel);
  }
  return out;
}
