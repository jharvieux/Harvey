// M7 (code layer, #170) — missing React hook dependencies, via the battle-tested
// react-hooks/exhaustive-deps rule run programmatically (ESLint Linter API, no config files,
// no shelling out). The #170 catalog files it under render perf, so findings land in §3b
// alongside the other M7C classes.
//
// Deliberately NOT a re-implementation: the upstream rule's dependency analysis is years of
// hardened edge cases. We only adapt its messages into Finding[] (rolled up per file, like
// the other high-count classes).
//
// #230: a 6-repo triage found ~0 real stale-closure/refetch bugs among 31 raw hits — every one
// was the rule firing on an effect already keyed to a primitive id (its actual dependency
// behavior was fine; the rule just wants the literal name in the array too). Reported as an
// Info-severity style note, not a Perf finding — visible in the report but not counted as work.

import { Linter } from "eslint";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";
import type { Finding } from "../findings.js";
import type { SourceInput } from "./common.js";
import { SOURCE_FILE } from "./load-sources.js";

const HOOK_CALL = /\buse(Effect|LayoutEffect|InsertionEffect|Memo|Callback|ImperativeHandle)\s*\(/;

const linter = new Linter();

function lintFile(file: SourceInput): { line: number; message: string }[] {
  const messages = linter.verify(
    file.text,
    {
      files: ["**/*.ts", "**/*.tsx", "**/*.jsx", "**/*.mjs", "**/*.cjs", "**/*.mts", "**/*.cts"], // flat config only matches .js by default
      languageOptions: {
        parser: tseslint.parser as Linter.Parser,
        parserOptions: { ecmaFeatures: { jsx: true }, sourceType: "module" },
      },
      plugins: { "react-hooks": reactHooks as never },
      rules: { "react-hooks/exhaustive-deps": "warn" },
    },
    file.path,
  );
  return messages
    .filter((m) => m.ruleId === "react-hooks/exhaustive-deps")
    .map((m) => ({ line: m.line, message: m.message }));
}

export function detectHookDepFindings(files: SourceInput[]): Finding[] {
  const findings: Finding[] = [];
  const unparseable: string[] = [];
  let n = 0;
  for (const file of files) {
    if (!SOURCE_FILE.test(file.path)) continue; // #1065: the loader's own filter, imported so the two can never drift apart
    if (!HOOK_CALL.test(file.text)) continue; // cheap pre-filter: no dep-taking hooks, no lint run
    let hits: { line: number; message: string }[];
    try {
      hits = lintFile(file);
    } catch {
      // #1083: this pass's own ESLint+typescript-eslint parser configuration failed on the file's
      // syntax. NOT a read failure — the shared loader (load-sources.ts) has no try/catch of its
      // own, so an unreadable file throws there and fails the whole pass loud before any file ever
      // reaches this detector. (The comment this replaces asserted "the other detectors already
      // skip it too" — unverified, and contradicted by `grep 'limitations.push|notes.push' src` :
      // no detector anywhere records a skip.) Counted below instead of silently dropped.
      unparseable.push(file.path);
      continue;
    }
    const first = hits[0];
    if (!first) continue;
    findings.push({
      id: `M7H-${String(++n).padStart(2, "0")}`,
      status: "Open",
      category: "Performance",
      title: `Hook dependency-list style note (${hits.length}× in ${file.path})`,
      severity: "Info",
      confidence: "Likely",
      taxonomy: "M7 — Missing hook dependencies",
      location: `${file.path}:${first.line}`,
      evidence: `react-hooks/exhaustive-deps: ${first.message}${hits.length > 1 ? ` (first of ${hits.length} in this file)` : ""} — a lint-style signal, not confirmed as a stale-closure or refetch bug.`,
      impact: "Usually benign (the rule wants the literal name added even when the effect's actual behavior is already correct); confirm before treating as a real stale-closure/refetch bug.",
      fix: "Apply the rule's suggested dependency list; if a dep changes every render, stabilize it (useMemo/useCallback) instead of omitting it.",
      value: 1,
      ease: 4,
      safety: 4,
    });
  }
  if (unparseable.length > 0) {
    findings.push({
      id: "M7H-00",
      status: "Open",
      category: "Coverage",
      title: `Hook-dependency lint could not parse ${unparseable.length} file${unparseable.length === 1 ? "" : "s"}`,
      severity: "Info",
      confidence: "N/A",
      taxonomy: "Coverage — hook-dependency lint parse failure",
      location: unparseable.slice(0, 5).join(", ") + (unparseable.length > 5 ? `, +${unparseable.length - 5} more` : ""),
      evidence: `react-hooks/exhaustive-deps could not be run against: ${unparseable.join(", ")} — this pass's ESLint+typescript-eslint configuration failed to parse the file.`,
      impact: "Any missing/stale hook-dependency issue in these specific files is NOT assessed by this pass.",
      fix: "Review these files by hand for missing-dependency / stale-closure bugs in useEffect/useMemo/useCallback/useLayoutEffect/useInsertionEffect/useImperativeHandle.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    });
  }
  return findings;
}
