// Scopes a scan target down to the files that should actually be scanned, so untracked/
// local working-tree artifacts never reach the mechanical tools (issue #101). The scanner
// walks a scratch copy of the target instead of the raw directory:
//
//   - git repo target: copy the git-TRACKED files only (`git ls-files`). This naturally
//     excludes anything gitignored/untracked — `.env.local`, `.claude/worktrees/`,
//     `node_modules`, `.next` — while still keeping a fixture that's deliberately committed
//     despite being gitignored (e.g. targets/calibration/.env.local, force-added for
//     calibration; see targets/calibration/GROUND-TRUTH.md). This is also what makes the
//     primary access path (git clone / collaborator invite) safe by construction: a clone
//     only ever has tracked files to begin with — the noise in issue #101 came from scanning
//     a local working checkout, not a clone.
//   - non-git target (a zip export or plain directory, per the runbook's zip-export access
//     option): no git index to consult, so fall back to a hard exclude list. This is
//     best-effort — without git history we can't tell a legitimately-committed `.env` from a
//     leaked working-tree one, so `.env*` is deliberately NOT excluded here (see issue #101's
//     scope-correction comment). Prefer git-clone access; this path exists for when a zip is
//     unavoidable.
//
// The scratch copy has no `.git` directory, so the git-history secret scan (which needs a
// real, clonable repo) must keep operating on the ORIGINAL directory — callers pass both.

import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";

const NON_GIT_EXCLUDE_DIRS = new Set([
  "node_modules", ".git", ".claude", ".next", "dist", "build", "coverage",
]);
const NON_GIT_EXCLUDE_FILE = /\.log$/;
const WORKTREE_DIR = /worktrees?$/i;

interface ScanScope {
  scanDir: string; // scratch dir to point filesystem-walking tools at
  cleanup: () => void;
}

function isGitWorkTree(dir: string): boolean {
  try {
    return execFileSync("git", ["-C", dir, "rev-parse", "--is-inside-work-tree"], { encoding: "utf8" }).trim() === "true";
  } catch {
    return false;
  }
}

// `git -C dir ls-files -z` (no pathspec) lists tracked files with paths relative to `dir`
// itself, not the repo root — exactly what we need to mirror into the scratch copy.
function trackedFiles(dir: string): string[] {
  const out = execFileSync("git", ["-C", dir, "ls-files", "-z"], { encoding: "utf8", maxBuffer: 1024 * 1024 * 64 });
  return out.split("\0").filter(Boolean);
}

// A tracked entry can be a SYMLINK, including one pointing at a directory (git mode 120000 —
// zenstack's packages/ide/vscode/res is one). Plain cpSync follows it, sees a directory and throws
// "Recursive option not enabled", which killed the whole scan on the first such repo. Copy the link
// VERBATIM instead of what it points at: an in-repo relative link still resolves inside the scratch
// copy, and a link out of the repo is left dangling rather than pulling an out-of-scope tree in.
function copyFile(src: string, dest: string): void {
  mkdirSync(dirname(dest), { recursive: true });
  cpSync(src, dest, { recursive: true, verbatimSymlinks: true });
}

function copyTracked(dir: string, dest: string): void {
  for (const rel of trackedFiles(dir)) {
    const src = join(dir, rel);
    // Staged deletion, submodule gitlink — or, MEASURED 2026-07-28 (#1451), a committed symlink
    // whose target does not resolve: `existsSync` follows the link, so a tracked dangling link is
    // dropped here too. That is why the git path never reproduced the crash the non-git path below
    // did, and it is worth naming rather than leaving as a happy accident — the shielding is one
    // `existsSync` wide, and every detector downstream was relying on it without saying so.
    if (!existsSync(src)) continue;
    copyFile(src, join(dest, rel));
  }
}

function copyExcluding(dir: string, dest: string): void {
  for (const { name: entry, path: src, isDirectory } of readEntriesSafe(dir).entries) {
    if (NON_GIT_EXCLUDE_DIRS.has(entry) || WORKTREE_DIR.test(entry) || NON_GIT_EXCLUDE_FILE.test(entry)) continue;
    if (isDirectory) copyExcluding(src, join(dest, entry));
    else copyFile(src, join(dest, entry));
  }
}

// Builds the scratch copy and returns it plus a cleanup callback. Callers MUST call cleanup()
// (e.g. in a finally block) once scanning is done.
export function resolveScanScope(dir: string): ScanScope {
  const scratch = mkdtempSync(join(tmpdir(), "harvey-scan-scope-"));
  if (isGitWorkTree(dir)) copyTracked(dir, scratch);
  else copyExcluding(dir, scratch);
  return { scanDir: scratch, cleanup: () => rmSync(scratch, { recursive: true, force: true }) };
}

// The scratch root is a fresh mkdtemp dir on every run, so any finding location that names it
// carries a path that is unique per-run and per-machine. That is invisible for a throwaway scan,
// but poisons a COMMITTED scan artifact: every location differs on every regeneration, burying
// the real diff (issue #285). Strip the scratch prefix wherever it appears so locations come out
// target-relative. Not anchored at the string start: locations may carry a "[source] " prefix or
// a " (pkg@version)" suffix around the path.
const SCAN_SCOPE_PREFIX = /\S*[/\\]harvey-scan-scope-[^/\\]+[/\\]/g;

export function relativizeScanScope(location: string): string {
  return location.replace(SCAN_SCOPE_PREFIX, "");
}
