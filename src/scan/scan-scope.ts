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
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { copyFilteredSourceTree } from "../source-copy.js";
import { productSourceInventoryForTarget } from "../source-inventory.js";

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

// Builds the scratch copy and returns it plus a cleanup callback. Callers MUST call cleanup()
// (e.g. in a finally block) once scanning is done.
export function resolveScanScope(dir: string): ScanScope {
  const scratch = mkdtempSync(join(tmpdir(), "harvey-scan-scope-"));
  const inventory = productSourceInventoryForTarget(dir);
  try {
    const tracked = isGitWorkTree(dir) ? trackedFiles(dir) : undefined;
    copyFilteredSourceTree(dir, scratch, (path) => !inventory.excludedDirectoryFor(path)
      && (tracked !== undefined || (!WORKTREE_DIR.test(basename(path)) && !NON_GIT_EXCLUDE_FILE.test(path))), tracked);
  } catch (error) {
    rmSync(scratch, { recursive: true, force: true });
    throw error;
  }
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
