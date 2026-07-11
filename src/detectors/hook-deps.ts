// M7 (code layer, #170) — missing React hook dependencies, via the battle-tested
// react-hooks/exhaustive-deps rule run programmatically (ESLint Linter API, no config files,
// no shelling out). A missing dep is both a correctness smell (stale closure) and a perf one
// (the effect/memo re-runs against stale inputs or is recreated to compensate); the #170
// catalog files it under render perf, so findings land in §3b alongside the other M7C classes.
//
// Deliberately NOT a re-implementation: the upstream rule's dependency analysis is years of
// hardened edge cases. We only adapt its messages into Finding[] (rolled up per file, like
// the other high-count classes).

import { Linter } from "eslint";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";
import type { Finding } from "../findings.js";
import type { SourceInput } from "./common.js";

const HOOK_CALL = /\buse(Effect|LayoutEffect|InsertionEffect|Memo|Callback|ImperativeHandle)\s*\(/;

const linter = new Linter();

function lintFile(file: SourceInput): { line: number; message: string }[] {
  const messages = linter.verify(
    file.text,
    {
      files: ["**/*.ts", "**/*.tsx", "**/*.jsx"], // flat config only matches .js by default
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
  let n = 0;
  for (const file of files) {
    if (!/\.(ts|tsx|jsx)$/.test(file.path)) continue;
    if (!HOOK_CALL.test(file.text)) continue; // cheap pre-filter: no dep-taking hooks, no lint run
    let hits: { line: number; message: string }[];
    try {
      hits = lintFile(file);
    } catch {
      continue; // unparseable file (syntax beyond the parser) — the other detectors already skip it too
    }
    const first = hits[0];
    if (!first) continue;
    findings.push({
      id: `M7H-${String(++n).padStart(2, "0")}`,
      status: "Open",
      category: "Performance",
      title: `Hook dependency-list problems (${hits.length}× in ${file.path})`,
      severity: "Low",
      confidence: "Likely",
      taxonomy: "M7 — Missing hook dependencies",
      location: `${file.path}:${first.line}`,
      evidence: `react-hooks/exhaustive-deps: ${first.message}${hits.length > 1 ? ` (first of ${hits.length} in this file)` : ""}`,
      impact:
        "Effects/memos run against stale values (subtle wrong-data bugs) or are compensated with over-broad deps that re-run every render — both waste renders and hide state bugs.",
      fix: "Apply the rule's suggested dependency list; if a dep changes every render, stabilize it (useMemo/useCallback) instead of omitting it.",
      value: 2,
      ease: 4,
      safety: 4,
    });
  }
  return findings;
}
