import { createHash } from "node:crypto";
import type { SourceInput } from "../detectors/common.js";
import {
  SOURCE_LANGUAGES,
  sourceLanguage,
  type SourceLanguage,
} from "../detectors/load-sources.js";
import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";

export type SourcePopulationModule = "M5" | "M6";
type SourcePopulationStatus = "examined" | "partial" | "not-assessed" | "not-applicable";

export interface SourcePopulationRow {
  language: SourceLanguage;
  identified: { count: number; pathsDigest: string };
  examined: { count: number; pathsDigest: string };
  status: SourcePopulationStatus;
  reason?: string;
  provenance: string;
  falsifier: string;
}

export interface SourcePopulationReceipt {
  schema: 1;
  module: SourcePopulationModule;
  populations: SourcePopulationRow[];
}

const SOURCE_POPULATION_PREFIX = "HARVEY_SOURCE_POPULATION ";
export const M5_PYTHON_EMPTY_HANDLER_TAXONOMY = "M5 — Python empty/pass exception handler";
export const M5_GO_LIBRARY_PANIC_TAXONOMY = "M5 — Go library panic";
export const M5_RUST_STUB_TAXONOMY = "M5 — Rust production stub or unsafe unwrap";

function pathsDigest(paths: readonly string[]): string {
  const hash = createHash("sha256");
  for (const path of [...paths].sort()) {
    hash.update(String(path.length));
    hash.update("\0");
    hash.update(path);
  }
  return hash.digest("hex");
}

function byLanguage(files: readonly SourceInput[], language: SourceLanguage): SourceInput[] {
  return files.filter((file) => sourceLanguage(file.path) === language);
}

function supportedLanguages(module: SourcePopulationModule): ReadonlySet<SourceLanguage> {
  return module === "M5"
    ? new Set(["javascript/typescript", "python", "go", "rust"])
    : new Set(["javascript/typescript"]);
}

export function sourcePopulationReceipt(module: SourcePopulationModule, files: readonly SourceInput[]): SourcePopulationReceipt {
  const supported = supportedLanguages(module);
  return {
    schema: 1,
    module,
    populations: SOURCE_LANGUAGES.map((language) => {
      const identifiedFiles = byLanguage(files, language);
      const examinedFiles = supported.has(language) ? identifiedFiles : [];
      const identified = { count: identifiedFiles.length, pathsDigest: pathsDigest(identifiedFiles.map((file) => file.path)) };
      const examined = { count: examinedFiles.length, pathsDigest: pathsDigest(examinedFiles.map((file) => file.path)) };
      if (identifiedFiles.length === 0) {
        return {
          language,
          identified,
          examined,
          status: "not-applicable" as const,
          reason: `No ${language} source files were identified in this consumer's product-source population.`,
          provenance: "src/detectors/load-sources.ts#loadSourceInventory",
          falsifier: `Add a tracked ${language} product source file and rerun detect-static.`,
        };
      }
      if (!supported.has(language)) {
        return {
          language,
          identified,
          examined,
          status: "not-assessed" as const,
          reason: `${module} has no calibrated ${language} source classifier; ${identified.count} identified file(s) received no clean-coverage credit.`,
          provenance: "src/scan/polyglot-quality.ts#sourcePopulationReceipt",
          falsifier: `Add a registry-owned ${module} ${language} classifier with calibrated positive/benign fixtures, then rerun detect-static.`,
        };
      }
      if (module === "M5" && language !== "javascript/typescript") {
        return {
          language,
          identified,
          examined,
          status: "partial" as const,
          reason: `All ${identified.count} ${language} file(s) were examined by a bounded high-signal rule set; this is not full semantic coverage.`,
          provenance: "src/scan/polyglot-quality.ts#detectM5PolyglotQualityFindings",
          falsifier: `Expand the calibrated ${language} rule set and update this receipt only when the consumer examines the added constructs.`,
        };
      }
      return {
        language,
        identified,
        examined,
        status: "examined" as const,
        provenance: module === "M5"
          ? "src/cli/static-detect.ts M5 JavaScript/TypeScript detector set"
          : "src/detectors/handrolled.ts#detectHandrolledFindings",
        falsifier: `Remove the ${module} ${language} classifier from static-detect or narrow its input population.`,
      };
    }),
  };
}

export function formatSourcePopulationReceipt(receipt: SourcePopulationReceipt): string {
  return `${SOURCE_POPULATION_PREFIX}${receipt.module} ${JSON.stringify(receipt)}`;
}

export function parseSourcePopulationReceipt(stdout: string, module: SourcePopulationModule): SourcePopulationReceipt | undefined {
  const prefix = `${SOURCE_POPULATION_PREFIX}${module} `;
  const line = stdout.split(/\r?\n/).find((candidate) => candidate.startsWith(prefix));
  if (!line) return undefined;
  try {
    const value = JSON.parse(line.slice(prefix.length)) as SourcePopulationReceipt;
    if (value.schema !== 1 || value.module !== module || !Array.isArray(value.populations)) return undefined;
    return value;
  } catch {
    return undefined;
  }
}

function lineLocation(file: SourceInput, offset: number): string {
  return `${file.path}:${file.text.slice(0, offset).split("\n").length}`;
}

function stableId(stem: string, file: SourceInput, offset: number): string {
  return `${stem}-${file.path.replace(/[^a-zA-Z0-9]+/g, "-")}-${offset}`;
}

function pythonFindings(file: SourceInput): Finding[] {
  const findings: Finding[] = [];
  const pattern = /except(?:\s+[^:\n]+)?\s*:\s*(?:#.*\n\s*)?(pass|\.\.\.)(?:\s*(?:#.*)?)?(?=\n|$)/g;
  for (const match of file.text.matchAll(pattern)) {
    const offset = match.index ?? 0;
    findings.push(mechanicalFinding({
      id: stableId("M5-PY-EMPTY-EXCEPT", file, offset),
      title: "Python exception handler silently discards a failure",
      severity: "Low",
      category: "Maintainability",
      taxonomy: M5_PYTHON_EMPTY_HANDLER_TAXONOMY,
      location: lineLocation(file, offset),
      evidence: `An except block contains only \`${match[1]}\`, so this failure path has no observable outcome.`,
      impact: "Callers can continue as though the operation succeeded while the original failure is hidden.",
      fix: "Propagate or wrap the exception, return an explicit failure, compensate, or document a narrowly justified ignored exception.",
      precisionTier: "review",
    }));
  }
  return findings;
}

function goFindings(file: SourceInput): Finding[] {
  if (/^\s*package\s+main\b/m.test(file.text)) return [];
  return [...file.text.matchAll(/\bpanic\s*\(/g)].map((match) => {
    const offset = match.index ?? 0;
    return mechanicalFinding({
      id: stableId("M5-GO-LIBRARY-PANIC", file, offset),
      title: "Go library code terminates the process with panic",
      severity: "Low",
      category: "Maintainability",
      taxonomy: M5_GO_LIBRARY_PANIC_TAXONOMY,
      location: lineLocation(file, offset),
      evidence: "A non-main Go package calls `panic(...)`; callers cannot recover through its normal error contract.",
      impact: "A recoverable library failure can terminate the hosting process or force callers to add an unsafe recovery boundary.",
      fix: "Return a descriptive error and let the application boundary decide whether the process must terminate.",
      precisionTier: "review",
    });
  });
}

function rustFindings(file: SourceInput): Finding[] {
  const rows: Finding[] = [];
  const patterns = [
    { pattern: /\b(?:todo|unimplemented)!\s*\(/g, detail: "A production Rust path contains a `todo!`/`unimplemented!` stub that panics when reached." },
    { pattern: /\bunsafe\s*\{[^{}]*\.unwrap\s*\(/gs, detail: "An `unsafe` block also calls `.unwrap()`, combining unchecked invariants with a panic path." },
  ];
  for (const { pattern, detail } of patterns) {
    for (const match of file.text.matchAll(pattern)) {
      const offset = match.index ?? 0;
      rows.push(mechanicalFinding({
        id: stableId("M5-RUST-STUB", file, offset),
        title: "Rust production path contains a panic-prone placeholder",
        severity: "Low",
        category: "Maintainability",
        taxonomy: M5_RUST_STUB_TAXONOMY,
        location: lineLocation(file, offset),
        evidence: detail,
        impact: "A reachable production path can panic instead of returning a typed failure.",
        fix: "Implement the branch or return a typed error; inside unsafe code, validate the invariant before unwrapping.",
        precisionTier: "review",
      }));
    }
  }
  return rows;
}

function m5PolyglotQualitySources(files: readonly SourceInput[]): SourceInput[] {
  return files.filter((file) => ["python", "go", "rust"].includes(sourceLanguage(file.path) ?? ""));
}

export function classifyM5PolyglotQualityFindings(files: readonly SourceInput[]): Finding[] {
  return m5PolyglotQualitySources(files).flatMap((file) => {
    switch (sourceLanguage(file.path)) {
      case "python": return pythonFindings(file);
      case "go": return goFindings(file);
      case "rust": return rustFindings(file);
      default: return [];
    }
  });
}

function sourcePopulationDisclosureFindings(receipt: SourcePopulationReceipt): Finding[] {
  return receipt.populations
    .filter((row) => row.identified.count > 0 && (row.status === "partial" || row.status === "not-assessed"))
    .map((row) => mechanicalFinding({
      id: `${receipt.module}-SOURCE-COVERAGE-${row.language.replace(/[^a-z0-9]+/gi, "-").toUpperCase()}`,
      title: `${receipt.module} ${row.language} source coverage is ${row.status}`,
      severity: "Info",
      category: "Coverage",
      taxonomy: `${receipt.module} — Source coverage ${row.status}: ${row.language}`,
      location: "(repo-wide)",
      evidence: `${row.reason} Identified=${row.identified.count} (${row.identified.pathsDigest}); examined=${row.examined.count} (${row.examined.pathsDigest}). Provenance: ${row.provenance}. Falsifier: ${row.falsifier}`,
      impact: "The audit does not present an unexamined or bounded source population as clean coverage.",
      fix: row.falsifier,
      precisionTier: "review",
      confidence: "N/A",
    }));
}

export function detectM5PolyglotQualityAndCoverageFindings(files: readonly SourceInput[]): Finding[] {
  const receipt = sourcePopulationReceipt("M5", files);
  return [...classifyM5PolyglotQualityFindings(files), ...sourcePopulationDisclosureFindings(receipt)];
}

export function detectM6PolyglotCoverageFindings(files: readonly SourceInput[]): Finding[] {
  return sourcePopulationDisclosureFindings(sourcePopulationReceipt("M6", files));
}
