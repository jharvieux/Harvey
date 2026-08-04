// Clone helper for jobs that measure the pinned external corpus. Extracted from
// src/cli/corpus-drift.ts when handrolled-frequency.ts (#406) became a second consumer.
//
// Fetch by exact commit rather than clone + checkout: baselines and measurements are only
// meaningful against the pinned tree, and `fetch --depth 1 <sha>` refuses rather than silently
// landing on HEAD if the pin ever disappears upstream (a force-push or a deleted repo must fail
// loudly, not re-baseline).

import { execFileSync } from "node:child_process";
import { cpSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";

export function cloneAtPin(repo: string, commit: string, into: string): void {
  const git = (...a: string[]): void => void execFileSync("git", ["-C", into, ...a], { stdio: ["ignore", "ignore", "pipe"] });
  execFileSync("git", ["init", "-q", into], { stdio: "inherit" });
  git("remote", "add", "origin", `https://github.com/${repo}`);
  git("fetch", "-q", "--depth", "1", "origin", commit);
  git("checkout", "-q", "FETCH_HEAD");
}

// A pin never changes without an edit to src/scan/external-corpus.ts, so its clone is safe to
// reuse across runs (#1571's corpus-clone-cache). `cacheDir`, when set (CI:
// $HARVEY_CORPUS_CACHE_DIR, restored by .github/actions/corpus-clone-cache), holds one pristine
// checkout per repo; corpus-drift's own working copies are still disposable mkdtemp dirs that COPY
// from here rather than fetch over the network, so --install/scanning can mutate or delete them
// exactly as before.
//
// Never trusts a cache entry blindly: `isFreshClone` checks it is AT the pinned commit with a
// clean working tree, and anything else — missing, wrong commit, a partial/corrupted checkout —
// is re-cloned fresh into the cache dir rather than used. That makes a broken cache cost network
// time for the one affected target, never a silently smaller corpus. CI's own preflight
// (corpus-clone-cache's verify step) already hard-fails on this shape before any target is
// scored; this check is what keeps a direct/local use of the cache dir just as safe.
export function cloneAtPinCached(repo: string, commit: string, into: string, cacheDir?: string): void {
  if (!cacheDir) {
    cloneAtPin(repo, commit, into);
    return;
  }
  const cached = join(cacheDir, repo.replace(/\//g, "__"));
  if (!isFreshClone(cached, commit)) {
    console.error(`  corpus-clone-cache: ${repo}@${commit.slice(0, 8)} not cached (or stale) — cloning fresh`);
    // A stale/corrupted slot can already be a git repo (e.g. the pin moved since it was
    // populated) — cloneAtPin assumes a slot it can `git init` and `remote add origin` into
    // clean, so a leftover .git here would collide with a stale "origin". Clear it first.
    rmSync(cached, { recursive: true, force: true });
    cloneAtPin(repo, commit, cached);
  }
  cpSync(cached, into, { recursive: true });
}

// Exported so the validity check itself is directly testable without a network clone (see
// corpus-clone.test.ts) — cloneAtPinCached is the only production caller.
export function isFreshClone(dir: string, commit: string): boolean {
  if (!existsSync(join(dir, ".git"))) return false;
  try {
    const head = execFileSync("git", ["-C", dir, "rev-parse", "HEAD"], { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
    if (head !== commit) return false;
    const status = execFileSync("git", ["-C", dir, "status", "--porcelain"], { stdio: ["ignore", "pipe", "ignore"] }).toString();
    return status.trim() === "";
  } catch {
    return false;
  }
}
