// #1301: a semgrep rule can ship tagged `precisionTier: "high"`, feed the client-facing free count
// and the A–F grade, and never have been validated against anything. #61 asked for that to be
// impossible and its CI enforcement was never built. This is the enforcement: every `harvey-*` rule
// in src/scan/rules/semgrep/ must be PAIRED — claimed by a planted positive it actually caught, and
// paired with a benign twin fixture it stayed silent on.
//
// It is scored against `dry-run/findings.json`, the committed artifact of the real scan over
// targets/calibration, so the check needs no binaries and runs under `pnpm verify`. That artifact
// is kept honest by the required `dry-run-drift` status check, which regenerates and diffs it.
//
// WHAT THE NEGATIVE HALF DOES AND DOES NOT PROVE — the link between a rule and its boundary
// negative is DERIVED FROM FIXTURE NAMES (`redos-regex.ts` ↔ `redos-regex-safe.ts`), not declared
// in the answer key, because CorpusEntry has no rule-id field. MEASURED 2026-07-28: the derivation
// resolves a twin for 110/110 rules. So it proves (a) a benign twin of this rule's own fixture
// exists in the corpus and (b) the rule produced nothing on it. It does NOT prove the twin
// exercises the specific sanitizer the rule implements — a declared rule↔entry link would, and is
// tracked as follow-up work. A rule that fires on many fixtures has many candidate twins, so the
// (a) half is weakest exactly where the rule is broadest.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { readNamesSafe } from "../fs-walk.js";
import { fileURLToPath } from "node:url";
import { CORPUS, scoreEntry, type CorpusEntry } from "./calibration.js";
import type { Finding } from "../findings.js";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

export interface SemgrepRule {
  id: string;
  file: string;
  // The taxonomy the finding actually carries. Normally the rule id under the semgrep config
  // prefix; a rule declaring metadata.harveyTaxonomy (#996) reports that instead, and keying on
  // the id alone would score those rules as "never fires".
  taxonomy: string;
}

export function harveySemgrepRules(): SemgrepRule[] {
  const dir = join(repoRoot, "src", "scan", "rules", "semgrep");
  const rules: SemgrepRule[] = [];
  for (const file of readNamesSafe(dir).filter((n) => n.endsWith(".yml"))) {
    for (const block of readFileSync(join(dir, file), "utf8").split(/^\s*-\s+id:\s*/m).slice(1)) {
      const id = /^(harvey-[a-z0-9-]+)/.exec(block)?.[1];
      if (!id) continue;
      rules.push({ id, file, taxonomy: /harveyTaxonomy:\s*"([^"]+)"/.exec(block)?.[1] ?? `src.scan.rules.semgrep.${id}` });
    }
  }
  return rules;
}

export function committedScanFindings(): Finding[] {
  const raw = JSON.parse(readFileSync(join(repoRoot, "dry-run", "findings.json"), "utf8")) as { findings?: Finding[] } | Finding[];
  return Array.isArray(raw) ? raw : (raw.findings ?? []);
}

const stem = (p: string): string => p.replace(/\.[a-z]+$/i, "");
const filePart = (location: string): string => location.replace(/^\[source\] /, "").split(":")[0] ?? location;
const BENIGN_SUFFIX = /-(safe|fixed|guarded|scoped|allowlist)$/;

interface RulePairing {
  rule: string;
  positives: string[]; // corpus entry ids a finding from this rule satisfies
  twin?: { entry: string; fixture: string };
  unpaired?: string; // why, when the rule is not fully paired
}

export function ruleCorpusPairings(
  rules: SemgrepRule[] = harveySemgrepRules(),
  findings: Finding[] = committedScanFindings(),
  corpus: CorpusEntry[] = CORPUS,
): RulePairing[] {
  const tracked = execFileSync("git", ["ls-files", "targets/calibration"], { cwd: repoRoot, encoding: "utf8" })
    .trim().split("\n").map((p) => p.replace(/^targets\/calibration\//, ""));
  const negativeFixtures = corpus
    .filter((e) => e.kind === "negative")
    .flatMap((e) => tracked.filter((p) => p.toLowerCase().includes(e.location.toLowerCase())).map((p) => ({ entry: e.id, fixture: p })));

  return rules.map(({ id, taxonomy }) => {
    const own = findings.filter((f) => f.taxonomy === taxonomy);
    const positives = corpus.filter((e) => e.kind === "positive" && scoreEntry(e, own).caughtTier !== undefined).map((e) => e.id);
    if (positives.length === 0) {
      return { rule: id, positives, unpaired: own.length === 0 ? "fires on nothing in targets/calibration — it has never been shown to work" : "fires, but no POSITIVE corpus entry scores it, so nothing would notice if it stopped" };
    }
    const firedStems = new Set(own.map((f) => stem(filePart(f.location))));
    const candidates = negativeFixtures.filter(({ fixture }) => {
      const s = stem(fixture);
      return [...firedStems].some((p) => s.startsWith(`${p}-`) || (s !== p && p.startsWith(s.replace(BENIGN_SUFFIX, ""))));
    });
    if (candidates.length === 0) return { rule: id, positives, unpaired: "no benign twin fixture — nothing proves it stays silent on the safe form of what it flags" };
    // A candidate the rule ALSO fired on proves nothing about silence. Several corpus fixtures are
    // shared files carrying both a planted defect and its benign sibling, so this is the normal
    // case, not an error — the rule is unpaired only when EVERY candidate carries one of its hits.
    const twin = candidates.find(({ fixture }) => !firedStems.has(stem(fixture)));
    if (!twin) return { rule: id, positives, unpaired: `every benign twin candidate (${candidates.map((c) => c.fixture).join(", ")}) also carries a hit from this rule — nothing shows it staying silent` };
    return { rule: id, positives, twin };
  });
}

// #1414 — WHAT SHARE OF THE FREE COUNT THIS GATE ACTUALLY COVERS, and the per-rule filter measured
// against it.
//
// #1301 shipped the pairing gate and a comment in quick-scan.ts asserting that an unvalidated rule
// never reaches a client's grade, because the build gate stops it reaching `main`. That sentence holds
// for `harvey-*` semgrep rules and ONLY for them — the gate enumerates `src/scan/rules/semgrep/*.yml`
// and nothing else — while
// `precisionTier: "high"` is set by AST detectors, the secret scanners, the dependency checks and
// third-party semgrep packs too, none of which this gate can see. So the claim was being made about
// the whole free count while covering part of it, and the size of the uncovered part was never
// measured.
//
// It is measured here, on every run, rather than written down: `coveredByPairingGate` /
// `outsidePairingGate` are counts over the committed scan, and a number that moves is the only kind
// that stays true. MEASURED 2026-07-31 against dry-run/findings.json — 157 high-tier findings, 104
// from an enumerated harvey-* rule, 53 (33.8%) from something else: committed credentials, the M1
// object-level-authz AST detector, static-RLS migration checks, dependency and license checks, and
// two third-party semgrep packs.
//
// `droppedByPerRuleGate` is #1414's requested prototype of the per-rule filter itself: the findings a
// free count gated on VALIDATION STATUS (rather than on the self-declared `precisionTier` tag) would
// withhold today. Per-RULE, not per-finding — dropping individual findings a corpus has no fixture
// for would trade a precision risk for a silent omission, the worse of the two, while dropping a
// whole unvalidated rule's output is exactly what #61 asked for. Its measured delta is 0 and stays 0
// by construction: `pnpm verify` fails on any unpaired rule, so an unpaired rule never reaches `main`
// and therefore never reaches a client scan. That is why the filter is reported here instead of being
// wired into selectFreeFindings — a runtime filter over a set the build gate keeps empty is a check
// with no failing direction, and this repo has spent this whole sweep removing those.
interface FreeCountCoverage {
  highTier: number;
  coveredByPairingGate: number;
  outsidePairingGate: number;
  outsideTaxonomies: string[];
  droppedByPerRuleGate: string[]; // finding ids a per-rule validation gate would withhold today
}

export function freeCountCoverage(
  findings: Finding[] = committedScanFindings(),
  rules: SemgrepRule[] = harveySemgrepRules(),
  pairings: RulePairing[] = ruleCorpusPairings(rules, findings),
): FreeCountCoverage {
  const ruleTaxonomies = new Set(rules.map((r) => r.taxonomy));
  const high = findings.filter((f) => f.precisionTier === "high");
  const outside = high.filter((f) => !ruleTaxonomies.has(f.taxonomy));
  const unpairedRules = new Set(pairings.filter((p) => p.unpaired).map((p) => p.rule));
  const unpairedTaxonomies = new Set(rules.filter((r) => unpairedRules.has(r.id)).map((r) => r.taxonomy));
  return {
    highTier: high.length,
    coveredByPairingGate: high.length - outside.length,
    outsidePairingGate: outside.length,
    outsideTaxonomies: [...new Set(outside.map((f) => f.taxonomy))].sort(),
    droppedByPerRuleGate: high.filter((f) => unpairedTaxonomies.has(f.taxonomy)).map((f) => f.id),
  };
}
