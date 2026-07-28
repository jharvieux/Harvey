// #1065 — the file-EXTENSION half of the coverage-disclosure family (M1-LANG-00 for languages M1
// cannot read, M1-SFC-00 for single-file components, INFRA-SCOPE-00 for infrastructure). It exists
// because the class it guards already bit us once: until 2026-07-25 the shared loader's SOURCE_FILE
// regex omitted `.js`/`.cjs`, so every loadSources-based pass (M5/M6/M7/M8/M9 and the M1 AST
// detectors) read almost nothing on a JavaScript codebase — and NOTHING in the output said so,
// because the only guard counted `package.json` as a scanned source file.
//
// The point of this row is that it is INDEPENDENT of the loader's own filter. SOURCE_LIKE below is
// a deliberately separate literal: it is the yardstick ("files a JS/TS product plausibly keeps its
// logic in"), and the LOADED paths handed in are ground truth. If the two ever disagree again —
// a new extension, an over-broad exclusion, a bug in the walk — the ratio moves and this row fires,
// without anyone having to remember to update it. Sharing the loader's regex would make the check
// tautological, which is exactly how the original gap stayed invisible.
//
// Falsifier: `pnpm detect-static <target>` on a tree of .js files must print a product-source count
// matching the .js file count, and must NOT emit M1-EXT-00.

import { readFileSync } from "node:fs";
import { extname, join, relative, sep } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import { EXCLUDED_DIR, isGeneratedSource } from "../detectors/load-sources.js";
import type { Finding } from "../findings.js";

// Independent of load-sources.ts's SOURCE_FILE by design (see header). Every JS/TS-family
// extension a product's own logic can live in.
const SOURCE_LIKE = /\.[cm]?[jt]sx?$/;

// Fire when at least this share of the target's source-like files went unread. Below it the
// shortfall is a stray minified vendor script, not a coverage hole worth a report row.
const UNREAD_SHARE_THRESHOLD = 0.1;

interface Unread {
  byExtension: Map<string, number>;
  generated: number;
  danglingLinks: number;
  example: string | undefined;
}

function scan(dir: string, loaded: Set<string>): { loadedCount: number; unread: Unread } {
  const unread: Unread = { byExtension: new Map(), generated: 0, danglingLinks: 0, example: undefined };
  let loadedCount = 0;
  const walk = (current: string): void => {
    const { entries, dangling } = readEntriesSafe(current);
    // #1451's residual, counted rather than chosen silently. Every walk in Harvey now SKIPS a
    // committed symlink whose target does not resolve — it has to, since following one throws and
    // discards the whole pass. A skipped link named `foo.ts` is nonetheless a source file nobody
    // read, and this row's whole job is loaded-vs-present. The population observed in the wild is
    // `.env` and `LICENSE.md` (5 links across the 15 #899 targets, none source-like), so this
    // ordinarily contributes 0 — which is the point: if it ever stops being 0, the row says so
    // instead of the file vanishing between "present" and "loaded".
    for (const name of dangling) {
      if (!SOURCE_LIKE.test(name)) continue;
      unread.danglingLinks += 1;
      unread.example ??= relative(dir, join(current, name)).split(sep).join("/");
    }
    for (const { name: entry, path: full, isDirectory } of entries) {
      if (isDirectory) {
        if (!EXCLUDED_DIR.test(entry)) walk(full);
        continue;
      }
      if (!SOURCE_LIKE.test(entry)) continue;
      const rel = relative(dir, full).split(sep).join("/");
      if (loaded.has(rel)) {
        loadedCount += 1;
        continue;
      }
      // Why it went unread, asked of the FILE rather than inferred from the loader's filter — the
      // filter is the thing under test, so reading the answer off it would make this tautological.
      if (isGeneratedSource(entry, readFileSync(full, "utf8"))) unread.generated += 1;
      else unread.byExtension.set(extname(entry), (unread.byExtension.get(extname(entry)) ?? 0) + 1);
      unread.example ??= rel;
    }
  };
  walk(dir);
  return { loadedCount, unread };
}

export function checkUnreadSourceExtensions(dir: string, loadedPaths: string[]): Finding[] {
  const { loadedCount, unread } = scan(dir, new Set(loadedPaths));
  const unreadCount = unread.generated + unread.danglingLinks + [...unread.byExtension.values()].reduce((a, b) => a + b, 0);
  const total = loadedCount + unreadCount;
  if (total === 0 || unreadCount / total < UNREAD_SHARE_THRESHOLD) return [];

  const ranked = [...unread.byExtension.entries()].sort((a, b) => b[1] - a[1]);
  const extSummary = ranked.map(([ext, n]) => `${ext} (${n} file${n === 1 ? "" : "s"})`).join("; ");
  const parts = [
    ...(ranked.length ? [`extensions the source loader does not read: ${extSummary}`] : []),
    ...(unread.generated ? [`${unread.generated} minified/generated file(s) excluded by decision (machine-generated output is not fixable in place)`] : []),
    ...(unread.danglingLinks ? [`${unread.danglingLinks} committed symlink(s) with a source extension whose target does not resolve in this checkout — skipped by every walk, because following one throws (#1451)`] : []),
  ];

  return [
    {
      id: "M1-EXT-00",
      title: `Source files not read by the static passes: ${unreadCount} of ${total}`,
      severity: "Info",
      confidence: "N/A",
      category: "Coverage",
      taxonomy: "Coverage — source files not read by the static/AST passes",
      location: "(repo-wide)",
      status: "Open",
      evidence: `The static/AST passes loaded ${loadedCount} of ${total} source-like files under the target (${Math.round((loadedCount / total) * 100)}%). Not read — ${parts.join("; ")}${unread.example ? `; e.g. ${unread.example}` : ""}.`,
      impact:
        "M5 (dead code), M6 (hand-rolled indicators), M7 (code-tier performance), M8 (test intent), M9 (App Router boundaries) and the TypeScript-side M1 tenant-scope/BOLA detectors report status having read only part of the codebase. Recorded so that the absence of findings for the unread files reads as 'not assessed', not 'assessed and clean'.",
      fix: "Review the unread files by hand for the classes Harvey's static passes check (dead code, duplication, perf anti-patterns, auth/tenant scoping). If an extension listed here is genuinely product source, add it to SOURCE_FILE in src/detectors/load-sources.ts and re-run.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    },
  ];
}
