// Clone helper for jobs that measure the pinned external corpus. Extracted from
// src/cli/corpus-drift.ts when handrolled-frequency.ts (#406) became a second consumer.
//
// Fetch by exact commit rather than clone + checkout: baselines and measurements are only
// meaningful against the pinned tree, and `fetch --depth 1 <sha>` refuses rather than silently
// landing on HEAD if the pin ever disappears upstream (a force-push or a deleted repo must fail
// loudly, not re-baseline).

import { execFileSync } from "node:child_process";

export function cloneAtPin(repo: string, commit: string, into: string): void {
  const git = (...a: string[]): void => void execFileSync("git", ["-C", into, ...a], { stdio: ["ignore", "ignore", "pipe"] });
  execFileSync("git", ["init", "-q", into], { stdio: "inherit" });
  git("remote", "add", "origin", `https://github.com/${repo}`);
  git("fetch", "-q", "--depth", "1", "origin", commit);
  git("checkout", "-q", "FETCH_HEAD");
}
