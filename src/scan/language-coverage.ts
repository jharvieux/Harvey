// #871 — languages M1's own analysis cannot read. MEASURED 2026-07-23: all 92 `harvey-*` semgrep
// rules in src/scan/rules/semgrep/ declare `languages: [javascript, typescript]`, and every
// tenant-scope AST detector parses TypeScript. So a Python worker, Go service or Ruby admin tool in
// the same repo, talking to the same tables, bypasses RLS with exactly the same effect as a broken
// policy — and M1 neither analyses it nor says it did not.
//
// This is the fail-loud half only, deliberately: the recommendation on #871 is NOT to chase
// multi-language SAST (that is ASPM's game). Detect the languages, count the files, disclose.
//
// Honest scope of the disclosure: Harvey's semgrep invocation also loads the third-party packs
// p/owasp-top-ten, p/secrets and p/security-audit (src/scan/semgrep.ts), which DO cover several of
// these languages for generic issues. What no rule covers is TENANT ISOLATION in them — that is
// what this row says, rather than the broader (and false) "not scanned at all".

import { extname, relative, sep } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import type { Finding } from "../findings.js";

// Server-side languages a second service in a multi-tenant repo is plausibly written in. Extension
// → display name; anything else (including .js/.ts, which M1 does analyse) is ignored.
const LANGUAGES: Record<string, string> = {
  ".py": "Python",
  ".go": "Go",
  ".rb": "Ruby",
  ".java": "Java",
  ".kt": "Kotlin",
  ".php": "PHP",
  ".cs": "C#",
  ".rs": "Rust",
  ".ex": "Elixir",
  ".exs": "Elixir",
  ".scala": "Scala",
};

const EXCLUDED_DIR = /^(node_modules|\.git|\.next|dist|build|coverage|out|vendor|venv|\.venv|__pycache__|target)$/;

interface LanguageHits {
  files: number;
  example: string;
}

function countUnanalysedLanguages(dir: string): Map<string, LanguageHits> {
  const byLanguage = new Map<string, LanguageHits>();
  const walk = (current: string): void => {
    for (const { name: entry, path: full, isDirectory } of readEntriesSafe(current).entries) {
      if (isDirectory) {
        if (!EXCLUDED_DIR.test(entry)) walk(full);
        continue;
      }
      const language = LANGUAGES[extname(entry)];
      if (!language) continue;
      const hit = byLanguage.get(language);
      if (hit) hit.files += 1;
      else byLanguage.set(language, { files: 1, example: relative(dir, full).split(sep).join("/") });
    }
  };
  walk(dir);
  return byLanguage;
}

export function checkUnanalysedLanguages(dir: string): Finding[] {
  const byLanguage = countUnanalysedLanguages(dir);
  if (byLanguage.size === 0) return [];

  const ranked = [...byLanguage.entries()].sort((a, b) => b[1].files - a[1].files);
  const summary = ranked.map(([lang, hit]) => `${lang} (${hit.files} file${hit.files === 1 ? "" : "s"}, e.g. ${hit.example})`).join("; ");
  return [
    {
      id: "M1-LANG-00",
      title: `Tenant isolation not assessed in ${ranked.map(([lang]) => lang).join("/")} source`,
      severity: "Info",
      confidence: "N/A",
      category: "Multi-tenant isolation",
      taxonomy: "Coverage — non-JS/TS source not analysed for tenant isolation",
      location: "(repo-wide)",
      status: "Open",
      evidence: `Source files in languages M1 cannot analyse were found in the target: ${summary}. Harvey's tenant-isolation rules are JavaScript/TypeScript-only (every custom semgrep rule declares \`languages: [javascript, typescript]\`, and the tenant-scope AST detectors parse TypeScript). The third-party packs Harvey also runs (p/owasp-top-ten, p/secrets, p/security-audit) cover some of these languages for generic issues, but none of them is tenant-isolation aware.`,
      impact:
        "A service in one of these languages that queries the same tables bypasses RLS with exactly the same effect as a broken policy — and it was NOT assessed for tenant scoping. Recorded so the absence of M1 findings for this code reads as 'not assessed', not 'assessed and clean'.",
      fix: "Review data access in these files by hand: every query must filter on the tenant/owner column, and any service-role/superuser database credential used from them must not be reachable by user input.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    },
  ];
}
