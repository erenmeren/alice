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
// jobs runner (jobEvent("x", ...)) and an event table ({"x", audit.Success, ...}). An action
// computed at run time is not found here.
const ACTION_PATTERNS = [
  /\bAction:\s*"([a-z][a-z0-9_.]*)"/g,
  /\.Action\s*=\s*"([a-z][a-z0-9_.]*)"/g,
  /\bappendAudit\([^"\n]*"([a-z][a-z0-9_.]*)"/g,
  /\bjobEvent\("([a-z][a-z0-9_.]*)"/g,
  /\{"([a-z][a-z0-9_]*\.[a-z0-9_.]+)",\s*audit\.(?:Success|Failure|Denied)\b/g,
];

export function auditActionsIn(src: string): string[] {
  const found = new Set<string>();
  for (const re of ACTION_PATTERNS) for (const m of src.matchAll(re)) found.add(m[1]);
  return [...found].sort();
}

// jobTypesIn finds the job type constants of internal/inventory/jobs.go (JobXxx = "type").
export function jobTypesIn(src: string): string[] {
  return [...src.matchAll(/^\s*Job\w*\s*=\s*"([a-z][a-z0-9_.]*)"/gm)].map((m) => m[1]).sort();
}

// backendAuditActions is every audit action literal in the packages that emit them.
export function backendAuditActions(): string[] {
  const found = new Set<string>();
  for (const dir of ['internal/inventory', 'internal/jobs', 'internal/api']) {
    for (const f of goFiles(dir)) for (const a of auditActionsIn(readRepoFile(f))) found.add(a);
  }
  return [...found].sort();
}

export function backendJobTypes(): string[] {
  return jobTypesIn(readRepoFile('internal/inventory/jobs.go'));
}

// goStringConsts finds the string constants of a Go source whose names match nameRe (for example
// /^StepName\w+$/): `Name = "value"` on its own line, with any spacing before the equals sign.
export function goStringConsts(src: string, nameRe: RegExp): string[] {
  const found = new Set<string>();
  for (const m of src.matchAll(/^\s*(?:const\s+)?([A-Za-z]\w*)\s*=\s*"([^"\n]*)"/gm)) if (nameRe.test(m[1])) found.add(m[2]);
  return [...found].sort();
}

export const goConsts = (rel: string, nameRe: RegExp): string[] => goStringConsts(readRepoFile(rel), nameRe);

// callArgsIn finds every string literal passed to a call such as warning("x").
export function callArgsIn(src: string, fn: string): string[] {
  return [...src.matchAll(new RegExp(`\\b${fn}\\("([^"\\n]*)"`, 'g'))].map((m) => m[1]).sort();
}
