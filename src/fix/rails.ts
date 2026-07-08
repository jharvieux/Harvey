// Safety rails: pure, deterministic checks the pipeline must clear before it
// writes, pushes, or opens a PR. Tested like findings.ts — these are the
// enforcement mirror of docs/design/fix-implementation.md §3.

import type { BlastRadius } from "./plan.js";

export interface RailCheck {
  ok: boolean;
  violation?: string;
}

// Non-overridable denylist (§3.1 rule 2). A fix that must touch these is, by
// definition, recommend-only — the pipeline never writes here.
const DENY_PATTERNS: readonly RegExp[] = [
  /(^|\/)\.env($|\.)/, // .env, .env.local, .env.production
  /(^|\/)secrets?(\/|\.|$)/i,
  /\.(pem|key|p12|pfx|crt)$/i,
  /credentials/i,
  /(^|\/)\.github\/workflows\//,
  /(^|\/)\.git\//,
];

// Push targets are Harvey fix branches only (§3.1 rule 1).
const FIX_REF = /^harvey\/fix\/.+$/;

const DEFAULT_PROTECTED_BRANCHES: readonly string[] = ["main", "master"];

export interface DiffCap {
  maxLines: number;
  maxFiles: number;
}

// §3.1 rule 4 default; operator-tunable per engagement, never per finding.
const DEFAULT_DIFF_CAP: DiffCap = { maxLines: 300, maxFiles: 10 };

function normalize(path: string): string {
  return path.replace(/^\.\//, "").replace(/\\/g, "/");
}

export function isDenied(path: string): boolean {
  const p = normalize(path);
  return DENY_PATTERNS.some((re) => re.test(p));
}

// Minimal glob support: `*` matches within a path segment, `**` matches across.
function globToRegExp(glob: string): RegExp {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*|\*/g, (m) => (m === "**" ? ".*" : "[^/]*"));
  return new RegExp(`^${escaped}$`);
}

export function isAllowed(path: string, allowlist: string[]): boolean {
  const p = normalize(path);
  return allowlist.some((pattern) => globToRegExp(normalize(pattern)).test(p));
}

// The implementer's write surface is the allowlist minus the denylist: deny wins.
export function checkPath(path: string, allowlist: string[]): RailCheck {
  if (isDenied(path)) return { ok: false, violation: `denylisted path (secrets/CI/git): ${path}` };
  if (!isAllowed(path, allowlist)) return { ok: false, violation: `outside engagement path allowlist: ${path}` };
  return { ok: true };
}

export function checkPushRef(ref: string): RailCheck {
  return FIX_REF.test(ref) ? { ok: true } : { ok: false, violation: `refusing push to non-fix ref: ${ref}` };
}

export function isProtectedBranch(branch: string, extraProtected: string[] = []): boolean {
  return [...DEFAULT_PROTECTED_BRANCHES, ...extraProtected].includes(branch);
}

export function checkDiffCap(blast: BlastRadius, cap: DiffCap = DEFAULT_DIFF_CAP): RailCheck {
  const touched = blast.files.length + blast.createdFiles.length;
  if (touched > cap.maxFiles) {
    return { ok: false, violation: `diff touches ${touched} files, cap is ${cap.maxFiles}` };
  }
  if (blast.estimatedChangedLines > cap.maxLines) {
    return { ok: false, violation: `diff is ~${blast.estimatedChangedLines} lines, cap is ${cap.maxLines}` };
  }
  return { ok: true };
}

// Full rail sweep over a plan's blast radius: every touched/created path must
// clear the allowlist and denylist, and the diff must fit the cap. Returns all
// violations so the operator sees the complete picture, not just the first.
export function checkBlastRadius(blast: BlastRadius, allowlist: string[], cap: DiffCap = DEFAULT_DIFF_CAP): RailCheck {
  const violations: string[] = [];
  for (const path of [...blast.files, ...blast.createdFiles]) {
    const r = checkPath(path, allowlist);
    if (!r.ok && r.violation) violations.push(r.violation);
  }
  const capCheck = checkDiffCap(blast, cap);
  if (!capCheck.ok && capCheck.violation) violations.push(capCheck.violation);
  return violations.length === 0 ? { ok: true } : { ok: false, violation: violations.join("; ") };
}
