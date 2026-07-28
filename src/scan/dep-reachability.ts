// Dependency-CVE reachability ordering (#874).
//
// The problem this solves is NOT "grade the CVEs". #213/#227 settled that a version-range match is
// not a proven vulnerability, so the whole "Dependency CVE" category stays out of the grade, and
// nothing here changes that — no finding produced or annotated by this module sets
// `exploitabilityVerified`. The consequence of that correct decision was the defect: the client got
// an unordered list of CVEs with a note saying we do not stand behind their exploitability, which
// reads as less mature than the honesty deserves.
//
// So this adds the one thing that can be measured cheaply and defended per row: IS THE PACKAGE
// ACTUALLY IMPORTED IN THIS CODEBASE? That is import-level reachability, and its limits are stated
// on every row it produces:
//
//   • `imported` does NOT mean the vulnerable function is called. Semgrep Supply Chain / Snyk /
//     Mend do function-level reachability; this is deliberately coarser and says so. It is an
//     ordering signal, not a verdict.
//   • `declared-not-imported` / `transitive-only` do NOT mean safe. A package can be reached
//     through another dependency, a build step, a config file, or dynamic loading this pass cannot
//     see. It is a DE-PRIORITIZATION signal, never a clearance — and the justification text says
//     that in the deliverable, not just here.
//   • When no source files can be read at all, the status is `not-assessed` and it sorts near the
//     TOP, not the bottom. An unmeasured row must never be presented as the least urgent one.

import { readFileSync } from "node:fs";
import { relative, sep } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import type { DependencyReachability, Finding, ReachabilityStatus } from "../findings.js";

const SOURCE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const EXCLUDED_DIR = /^(node_modules|\.next|\.git|dist|build|coverage|out)$/;
const FILES_CITED = 3;

// Sort order for the CVE list. Lower ranks first. `not-assessed` deliberately outranks both
// "we looked and it isn't imported" statuses.
const RANK: Record<ReachabilityStatus, number> = {
  imported: 0,
  "not-assessed": 1,
  "declared-not-imported": 2,
  "transitive-only": 3,
};

const CAVEAT = "Import-level reachability only — it does not prove the vulnerable function is called. Ordering signal, not a verdict.";

interface SourceFile {
  path: string;
  text: string;
}

function loadScannableSources(root: string): SourceFile[] {
  const files: SourceFile[] = [];
  const walk = (dir: string): void => {
    for (const { name: entry, path: full, isDirectory } of readEntriesSafe(dir).entries) {
      if (isDirectory) {
        if (!EXCLUDED_DIR.test(entry)) walk(full);
      } else if (SOURCE_FILE.test(entry)) {
        files.push({ path: relative(root, full).split(sep).join("/"), text: readFileSync(full, "utf8") });
      }
    }
  };
  walk(root);
  return files;
}

// Every module-specifier form that brings a package's code in: static import, re-export, CJS
// require, and dynamic import. A subpath ("lodash/merge") counts as importing "lodash".
function importsPackage(text: string, pkg: string): boolean {
  const escaped = pkg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const spec = `${escaped}(?:/[^"'\`]*)?`;
  const patterns = [
    new RegExp(`\\bfrom\\s*["'\`]${spec}["'\`]`),
    new RegExp(`\\bimport\\s*["'\`]${spec}["'\`]`),
    new RegExp(`\\b(?:require|import)\\s*\\(\\s*["'\`]${spec}["'\`]\\s*\\)`),
  ];
  return patterns.some((p) => p.test(text));
}

export function filesImporting(sources: SourceFile[], pkg: string): string[] {
  return sources.filter((f) => importsPackage(f.text, pkg)).map((f) => f.path);
}

export function classifyReachability(pkg: string, importingFiles: string[], directDeps: Set<string>, sourcesScanned: number): DependencyReachability {
  if (sourcesScanned === 0) {
    return {
      status: "not-assessed",
      rank: RANK["not-assessed"],
      justification: `No source files were available to scan, so whether ${pkg} is imported was NOT assessed. Ranked above the not-imported findings deliberately: an unmeasured dependency is not a low-priority one.`,
    };
  }
  if (importingFiles.length > 0) {
    const cited = importingFiles.slice(0, FILES_CITED).join(", ");
    const more = importingFiles.length > FILES_CITED ? `, +${importingFiles.length - FILES_CITED} more` : "";
    return {
      status: "imported",
      rank: RANK.imported,
      files: importingFiles,
      justification: `${pkg} is imported in ${importingFiles.length} source file(s): ${cited}${more}. ${CAVEAT}`,
    };
  }
  if (directDeps.has(pkg)) {
    return {
      status: "declared-not-imported",
      rank: RANK["declared-not-imported"],
      justification: `${pkg} is declared in the manifest but no scanned source file imports it. It may still be reached through another dependency, a build step, or dynamic loading — this de-prioritizes the row, it does not clear it.`,
    };
  }
  return {
    status: "transitive-only",
    rank: RANK["transitive-only"],
    justification: `${pkg} is not a direct dependency and no scanned source file imports it — it is pulled in by another package. Your own code does not call it directly, but the package that does may. De-prioritizes the row, does not clear it.`,
  };
}

// Attaches reachability to every Dependency CVE finding that names its package. A finding in that
// category with no `dependency` is left alone and COUNTED, so the disclosure below can say how many
// rows could not be ranked instead of leaving them silently unranked at the bottom of a sorted list.
export function annotateCveReachability(findings: Finding[], scanDir: string, directDeps: Set<string>): { findings: Finding[]; unranked: number } {
  const needsRanking = findings.some((f) => f.category === "Dependency CVE" && f.dependency);
  if (!needsRanking) return { findings, unranked: 0 };

  const sources = loadScannableSources(scanDir);
  const cache = new Map<string, DependencyReachability>();
  let unranked = 0;

  const annotated = findings.map((f) => {
    if (f.category !== "Dependency CVE") return f;
    if (!f.dependency) {
      // A coverage-disclosure row (DEP-OSV-00) names no package and is not a CVE to rank.
      if (f.taxonomy !== "Known-vulnerable dependency") return f;
      unranked++;
      return f;
    }
    let reach = cache.get(f.dependency);
    if (!reach) {
      reach = classifyReachability(f.dependency, filesImporting(sources, f.dependency), directDeps, sources.length);
      cache.set(f.dependency, reach);
    }
    return { ...f, reachability: reach };
  });

  return { findings: annotated, unranked };
}

// A CVE finding that reached the reachability pass without naming its package cannot be ranked.
// Left alone it would sort to the bottom of the list and read as the least urgent row — the silent
// omission this repo treats as worse than a wrong status. So it is stated in the output.
export function unrankedCveDisclosure(count: number): Finding {
  return {
    id: "DEP-REACH-00",
    title: `${count} dependency-CVE finding(s) could not be ranked by reachability`,
    severity: "Info",
    confidence: "N/A",
    category: "Dependency CVE",
    taxonomy: "Known-vulnerable dependency — reachability not assessed",
    location: "(repo-wide)",
    status: "Open",
    evidence: `${count} finding(s) in the Dependency CVE category did not name the package they concern, so the import-level reachability pass could not classify them.`,
    impact: "Those rows carry no reachability ordering. Their position in a sorted CVE list means nothing — do not read it as low priority.",
    fix: "Set `dependency` on the emitting check in src/scan/dependencies.ts so the row can be ranked.",
    value: 1,
    ease: 4,
    safety: 5,
  };
}

// The presentation order for a CVE list: reachability first, then severity. Callers that show CVEs
// (the free report's informational section, the deliverable) sort with this so the row a client
// should look at first is first.
export function byReachabilityThenSeverity(severityRank: (f: Finding) => number): (a: Finding, b: Finding) => number {
  return (a, b) => (a.reachability?.rank ?? RANK["not-assessed"]) - (b.reachability?.rank ?? RANK["not-assessed"]) || severityRank(a) - severityRank(b);
}
