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
