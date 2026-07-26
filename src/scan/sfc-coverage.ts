// #919 — single-file-component source (.svelte/.vue/.astro) is invisible to every static/AST pass
// AND was, until this file, uncounted too. MEASURED 2026-07-24 (read the code): the shared source
// loader (src/detectors/load-sources.ts, SOURCE_FILE) never loads these
// formats, so every consumer downstream of it — the M5 slop/dead-code detectors, M6 hand-rolled
// indicators, M7 code-tier performance, M9 App Router boundaries, and the TypeScript-side M1 AST
// detectors — reports status on a SvelteKit/Nuxt/Astro target having read almost none of its
// actual component code, with nothing in the output saying so.
//
// #871 (src/scan/language-coverage.ts, M1-LANG-00) closed the same shape of gap for non-JS/TS
// server languages; #903 closed it for non-Next frameworks (M9 N/A). This sits between the two and
// follows the same doctrine: detect, count, disclose — do NOT build SFC parsing here (that is the
// deferred #920 enabler). Kept a separate file rather than folding into language-coverage.ts: a
// concurrent M9-framework-porting batch (#916) may also touch that file, and this concern
// (counting a different FILE TYPE, not a different LANGUAGE) is unrelated to it.
//
// REASON: the shared source loader reads only .ts/.tsx/.jsx/.mjs, so no static/AST pass in Harvey sees a .svelte/.vue/.astro component — this file counts and discloses what is unread rather than parsing it (#920 is the parse layer)
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-26 (re-ran the falsifier below; it exits 1 — SOURCE_FILE is still ts/tsx/jsx/js/mjs/cjs/mts/cts only). The 2026-07-25 form matched anywhere in the file and started reporting STALE the same day, on `.svelte-kit` in EXCLUDED_DIR — an SFC directory being SKIPPED is the opposite of the loader learning to read one, so it is now pinned to the SOURCE_FILE line.
// FALSIFIER: grep -E "^export const SOURCE_FILE" src/detectors/load-sources.ts | grep -Eq "svelte|vue|astro"
// TOUCHES: src/detectors/load-sources.ts

import { readdirSync, statSync } from "node:fs";
import { extname, join, relative, sep } from "node:path";
import { SOURCE_FILE as ANALYSED_FILE } from "../detectors/load-sources.js";
import type { Finding } from "../findings.js";

// Extension → display name. Anything else (including the JS/TS-family extensions load-sources.ts
// DOES load) is ignored here.
const SFC_LANGUAGES: Record<string, string> = {
  ".svelte": "Svelte",
  ".vue": "Vue",
  ".astro": "Astro",
};

// #1065: this used to be a hand-copied duplicate of load-sources.ts's SOURCE_FILE, and it drifted —
// both omitted `.js`, so a barely-read plain-JavaScript repo reported a high analysed-proportion
// (the `.js` files were neither analysed nor in the denominator). Import the loader's own regex so
// the ratio can never again be measured against a stale copy of what it reads.
const EXCLUDED_DIR = /^(node_modules|\.git|\.next|dist|build|coverage|out|vendor)$/;

interface SfcHits {
  files: number;
  example: string;
}

function scan(dir: string): { sfc: Map<string, SfcHits>; analysedCount: number } {
  const sfc = new Map<string, SfcHits>();
  let analysedCount = 0;
  const walk = (current: string): void => {
    for (const entry of readdirSync(current)) {
      const full = join(current, entry);
      if (statSync(full).isDirectory()) {
        if (!EXCLUDED_DIR.test(entry)) walk(full);
        continue;
      }
      const language = SFC_LANGUAGES[extname(entry)];
      if (language) {
        const hit = sfc.get(language);
        const relPath = relative(dir, full).split(sep).join("/");
        if (hit) hit.files += 1;
        else sfc.set(language, { files: 1, example: relPath });
      } else if (ANALYSED_FILE.test(entry)) {
        analysedCount += 1;
      }
    }
  };
  walk(dir);
  return { sfc, analysedCount };
}

export function checkUnassessedSfcFiles(dir: string): Finding[] {
  const { sfc, analysedCount } = scan(dir);
  if (sfc.size === 0) return [];

  const ranked = [...sfc.entries()].sort((a, b) => b[1].files - a[1].files);
  const sfcTotal = ranked.reduce((sum, [, hit]) => sum + hit.files, 0);
  const totalSourceLike = analysedCount + sfcTotal;
  const summary = ranked.map(([lang, hit]) => `${lang} (${hit.files} file${hit.files === 1 ? "" : "s"}, e.g. ${hit.example})`).join("; ");
  // "State the proportion where it is knowable" (#919 acceptance criteria) — measured against the
  // same file-type universe load-sources.ts's own SOURCE_FILE recognizes, not a guess.
  const proportion = ` — M5/M6/M7/M9 and the M1 AST detectors analysed ${analysedCount} of ${totalSourceLike} source files (${Math.round((analysedCount / totalSourceLike) * 100)}%)`;

  return [
    {
      id: "M1-SFC-00",
      title: `Single-file-component source not analysed: ${ranked.map(([lang]) => lang).join("/")}`,
      severity: "Info",
      confidence: "N/A",
      category: "Coverage",
      taxonomy: "Coverage — single-file-component (.svelte/.vue/.astro) source not analysed",
      location: "(repo-wide)",
      status: "Open",
      evidence: `Source files in formats no Harvey static/AST pass reads were found in the target: ${summary}.${proportion}. The shared source loader (src/detectors/load-sources.ts) and every detector module's own file-extension filter recognise only JavaScript/TypeScript source — none parse Svelte/Vue/Astro single-file components.`,
      impact:
        "On a SvelteKit/Nuxt/Astro app whose logic lives mostly in these files, M5 (dead code), M6 (hand-rolled indicators), M7 (code-tier performance), M9 (App Router boundaries), and the TypeScript-side M1 tenant-scope/BOLA detectors report status having read almost none of the actual codebase. Recorded here so that absence reads as 'not assessed', not 'assessed and clean' — the same failure #871/#903 exist to prevent for other coverage gaps.",
      fix: "Review these files by hand for the same classes Harvey's static passes check in .ts/.tsx (dead code, duplication, perf anti-patterns, auth/tenant scoping) until SFC parsing support lands (tracked separately, #920).",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    },
  ];
}
