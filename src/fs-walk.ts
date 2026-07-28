// The one place in Harvey allowed to call `statSync` or `readdirSync`. Every directory read routes
// through here.
//
// WHY A BAN AND NOT JUST A HELPER: `statSync(p).isDirectory()` FOLLOWS symlinks and throws on one
// that does not resolve. Committed dangling links are routine in real repos — a link into a
// gitignored file (`.env`), an EE `LICENSE.md` — and #944 fixed exactly this in mutation-scan on
// 2026-07-24, after which src/scan/codebase-size.ts landed a fresh unguarded copy on 2026-07-25,
// one day later. #766 had already extracted `walkSourceFiles` "so a fix/hardening lands once, not
// three times" and it drifted anyway: an extracted helper is an AVAILABILITY, and nothing obliges
// new code to reach for it. What changes here is that the raw primitive is a CONSTRAINT —
// `src/fs-walk.test.ts` fails `pnpm verify` on any `statSync`/`readdirSync` token outside this file, over a
// discovery-backed sweep of src/ and tools/. A walker written next month is in scope the day it is
// written, so landing one unguarded takes deleting a gate rather than forgetting a helper.
//
// The crash matters more than a crash usually does: these walkers run near the END of a scan, so
// the throw discards a COMPLETED pass. MEASURED 2026-07-28 over the 15 #899 breadth targets — M1
// went 336→10 (liam), 1625→9 (dub), 1951→0 (cal-diy) after 118–235 s of semgrep, secret and
// dependency work, with `--findings-out` never written.
//
// BOUND (stated because a rule that declares one must say so, #1317): the gate bans the `statSync`
// and `readdirSync` tokens — the second because the crash has a shape that never stats at all (a
// names-only walk keeps the unresolvable link, and the readFileSync after it throws; MEASURED
// 2026-07-28, six live sites of that shape). `fs.promises.stat`, `statfsSync`, `realpathSync`,
// `opendirSync` and an `await readdir()` are outside it — none is in the tree today, so banning
// them would be a rule with a population of zero (#1345). Add them here the day one lands.

import { readdirSync, statSync, type Stats } from "node:fs";
import { join } from "node:path";

export interface SafeDirEntry {
  name: string;
  path: string;
  isDirectory: boolean;
}

// MEASURED 2026-07-28 (node 24, darwin) against the three ways a committed link fails to resolve:
// a link to a missing path throws ENOENT, a link THROUGH a non-directory throws ENOTDIR, and a link
// cycle throws ELOOP. `{ throwIfNoEntry: false }` absorbs the first two and returns undefined; it
// does NOT absorb ELOOP, which is why the explicit catch is here — the `existsSync` guard this
// replaces (#944, a91c2f9) survived all three, and a straight port to `throwIfNoEntry` alone would
// have quietly narrowed it. Anything else (EACCES on an unreadable tree) still throws: swallowing
// that would turn a permissions problem into a silently unscanned file, which is the inversion the
// disclosure-row family exists to prevent.
export function statSafe(path: string): Stats | undefined {
  try {
    return statSync(path, { throwIfNoEntry: false });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ELOOP") return undefined;
    throw err;
  }
}

export function isDirectorySafe(path: string): boolean {
  return statSafe(path)?.isDirectory() ?? false;
}

// Default-safe by construction: unresolvable links land in `dangling`, not `entries`, so a caller
// has nothing to remember before `readFileSync`. `dangling` carries those names out rather
// than dropping them, because a skipped link named `foo.ts` is a source file that went unscanned —
// M1-EXT-00 counts them so the omission is stated instead of chosen silently.
export function readEntriesSafe(dir: string): { entries: SafeDirEntry[]; dangling: string[] } {
  const entries: SafeDirEntry[] = [];
  const dangling: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, e.name);
    if (!e.isSymbolicLink()) {
      entries.push({ name: e.name, path, isDirectory: e.isDirectory() });
      continue;
    }
    const st = statSafe(path);
    if (st) entries.push({ name: e.name, path, isDirectory: st.isDirectory() });
    else dangling.push(e.name);
  }
  return { entries, dangling };
}

// The names-only form, for the call sites that filter by extension and then read. Those are just as
// exposed as a stat-based walk — the entry is not a directory, so the walker keeps it, and the
// readFileSync is what throws. MEASURED 2026-07-28: six live crash sites of exactly that shape
// (supabase-static's three migration/auth walkers, gha-permissions, bundle-stats' Vite pass), none
// of which contained a `statSync` and so none of which the first half of this guard would have seen.
export function readNamesSafe(dir: string): string[] {
  return readEntriesSafe(dir).entries.map((e) => e.name);
}

// Replaces `readdirSync(dir, { recursive: true })`. Deliberately re-implemented on readEntriesSafe
// rather than filtering node's recursive listing afterwards: filtering would stat every entry, and
// this way an unresolvable link costs nothing extra and a directory below one is simply not
// descended into. Paths come back relative to `dir`, matching what the recursive flag returns.
export function readRecursiveSafe(dir: string): string[] {
  const out: string[] = [];
  const walk = (current: string, prefix: string): void => {
    for (const { name, path, isDirectory } of readEntriesSafe(current).entries) {
      const rel = prefix ? `${prefix}/${name}` : name;
      out.push(rel);
      if (isDirectory) walk(path, rel);
    }
  };
  walk(dir, "");
  return out;
}
