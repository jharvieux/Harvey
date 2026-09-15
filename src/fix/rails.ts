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
export const DEFAULT_DIFF_CAP: DiffCap = { maxLines: 300, maxFiles: 10 };

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

// Turning a unified diff into the file lists + line count the checks above consume. This is the one
// diff parser in the fix subsystem — both the executing path (execute.ts) and the ticket path
// (trackers/fix-diff.ts) rail-check through it, so a denylisted or oversized diff is refused the same
// way whether it is heading for a worktree or a client ticket body.
interface DiffFacts {
  files: string[]; // paths the diff modifies or deletes
  createdFiles: string[]; // paths the diff adds
  changedLines: number; // added + removed body lines
  unsupportedMetadata: string[]; // patch forms the fix pipeline refuses before git apply
}

function decodeGitPath(raw: string): string | undefined {
  const value = raw;
  if (!value.startsWith('"')) return value;
  if (!value.endsWith('"')) return undefined;
  const bytes: number[] = [];
  for (let i = 1; i < value.length - 1; i++) {
    const char = value[i] as string;
    if (char !== "\\") {
      const codePoint = value.codePointAt(i);
      if (codePoint === undefined) return undefined;
      bytes.push(...Buffer.from(String.fromCodePoint(codePoint)));
      if (codePoint > 0xffff) i++;
      continue;
    }
    const escaped = value[++i];
    if (escaped === undefined) return undefined;
    const simple: Record<string, number> = { a: 7, b: 8, t: 9, n: 10, v: 11, f: 12, r: 13, '"': 34, "\\": 92 };
    if (simple[escaped] !== undefined) {
      bytes.push(simple[escaped]);
      continue;
    }
    if (/[0-7]/.test(escaped)) {
      let octal = escaped;
      while (octal.length < 3 && /[0-7]/.test(value[i + 1] ?? "")) octal += value[++i];
      bytes.push(Number.parseInt(octal, 8));
      continue;
    }
    return undefined;
  }
  return Buffer.from(bytes).toString("utf8");
}

function gitPathField(raw: string): string | undefined {
  if (!raw.startsWith('"')) return raw.split("\t")[0];
  let escaped = false;
  for (let i = 1; i < raw.length; i++) {
    const char = raw[i] as string;
    if (escaped) escaped = false;
    else if (char === "\\") escaped = true;
    else if (char === '"') return raw.slice(0, i + 1);
  }
  return undefined;
}

function stripPrefix(raw: string): string | undefined {
  const field = gitPathField(raw);
  const path = field === undefined ? "" : decodeGitPath(field) ?? "";
  if (path === "" || path === "/dev/null") return undefined;
  return path.replace(/^[ab]\//, "");
}

function parseDiffGitPaths(line: string): { oldPath: string; newPath: string }[] {
  const payload = line.slice("diff --git ".length);
  const candidates: { oldPath: string; newPath: string }[] = [];
  let quoted = false;
  let escaped = false;
  for (let i = 0; i < payload.length; i++) {
    const char = payload[i] as string;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && char === "\\") {
      escaped = true;
      continue;
    }
    if (char === '"') {
      quoted = !quoted;
      continue;
    }
    if (char !== " " || quoted) continue;
    const oldField = payload.slice(0, i);
    const newField = payload.slice(i + 1);
    const oldDecoded = decodeGitPath(oldField);
    const newDecoded = decodeGitPath(newField);
    if (!oldDecoded?.startsWith("a/") || !newDecoded?.startsWith("b/")) continue;
    candidates.push({ oldPath: oldDecoded.slice(2), newPath: newDecoded.slice(2) });
  }
  return candidates;
}

// Hunk headers carry exact old/new line counts, so the body is consumed by count rather than by
// looking for the next `---`. Content matters: removing a SQL comment produces a body line that
// reads `--- foo`, and a header-sniffing parser would take it for a new file header.
function parseHunkCounts(line: string): { oldLines: number; newLines: number } | undefined {
  const m = /^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/.exec(line);
  if (!m) return undefined;
  return { oldLines: m[1] === undefined ? 1 : Number(m[1]), newLines: m[2] === undefined ? 1 : Number(m[2]) };
}

export function parseDiffFacts(diff: string): DiffFacts {
  const files = new Set<string>();
  const createdFiles = new Set<string>();
  const unsupportedMetadata = new Set<string>();
  let changedLines = 0;
  let oldPath: string | undefined;
  let oldIsDevNull = false;
  let headerPaths: { oldPath: string; newPath: string }[] = [];
  let remainingOld = 0;
  let remainingNew = 0;

  const accountHeader = () => {
    for (const paths of headerPaths) {
      if (paths.oldPath === paths.newPath) {
        if (!createdFiles.has(paths.oldPath)) files.add(paths.oldPath);
      } else {
        files.add(paths.oldPath);
        createdFiles.add(paths.newPath);
      }
    }
  };

  for (const line of diff.split("\n")) {
    if (remainingOld > 0 || remainingNew > 0) {
      if (line.startsWith("\\")) continue; // "\ No newline at end of file"
      if (line.startsWith("+")) {
        remainingNew--;
        changedLines++;
      } else if (line.startsWith("-")) {
        remainingOld--;
        changedLines++;
      } else {
        remainingOld--;
        remainingNew--;
      }
      continue;
    }
    if (line.startsWith("diff --git ")) {
      accountHeader();
      headerPaths = parseDiffGitPaths(line);
      oldPath = undefined;
      oldIsDevNull = false;
      if (headerPaths.length === 0) unsupportedMetadata.add("unparseable Git diff header is unsupported");
      continue;
    }
    const hunk = parseHunkCounts(line);
    if (hunk) {
      remainingOld = hunk.oldLines;
      remainingNew = hunk.newLines;
      continue;
    }
    const endpoint = /^(rename|copy) (from|to) (.+)$/.exec(line);
    if (endpoint) {
      const path = decodeGitPath(endpoint[3] as string);
      if (!path) unsupportedMetadata.add(`unparseable Git ${endpoint[1]} ${endpoint[2]} path is unsupported`);
      else if (endpoint[2] === "from") files.add(path);
      else createdFiles.add(path);
      continue;
    }
    const mode = /^(?:old mode|new mode|new file mode|deleted file mode) (\d+)$/.exec(line)?.[1];
    if (mode === "120000") unsupportedMetadata.add("symlink patch metadata is unsupported");
    if (mode === "160000") unsupportedMetadata.add("gitlink patch metadata is unsupported");
    const indexedMode = /^index \S+\.\.\S+ (\d+)$/.exec(line)?.[1];
    if (indexedMode === "120000") unsupportedMetadata.add("symlink patch metadata is unsupported");
    if (indexedMode === "160000") unsupportedMetadata.add("gitlink patch metadata is unsupported");
    if (line === "GIT binary patch" || /^Binary files .+ differ$/.test(line)) {
      unsupportedMetadata.add("binary patch metadata is unsupported");
      continue;
    }
    if (line.startsWith("--- ")) {
      oldPath = stripPrefix(line.slice(4));
      oldIsDevNull = oldPath === undefined;
      continue;
    }
    if (line.startsWith("+++ ")) {
      const path = stripPrefix(line.slice(4)) ?? oldPath;
      if (oldIsDevNull) {
        if (path !== undefined) createdFiles.add(path);
      } else if (path === oldPath) {
        if (path !== undefined) files.add(path);
      } else {
        if (oldPath !== undefined) files.add(oldPath);
        if (path !== undefined) createdFiles.add(path);
      }
    }
  }
  accountHeader();
  return { files: [...files], createdFiles: [...createdFiles], changedLines, unsupportedMetadata: [...unsupportedMetadata] };
}

// behaviorPreserving is not knowable from a diff, so it is stated conservatively; the rail checks
// read only the path lists and the line count.
export function blastRadiusOf(facts: DiffFacts): BlastRadius {
  return {
    files: facts.files,
    createdFiles: facts.createdFiles,
    symbols: [],
    callers: [],
    behaviorPreserving: false,
    estimatedChangedLines: facts.changedLines,
  };
}
