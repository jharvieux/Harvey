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
// in the answer key, because CorpusEntry has no rule-id field.
//
// The line that stood here until #1676 — "MEASURED 2026-07-28: the derivation resolves a twin for
// 110/110 rules" — was an ARTEFACT of the `stem` bug fixed below: a bare dotfile collapsed to the
// empty string, so `.npmrc` answered as a benign twin for every rule. RE-MEASURED 2026-08-01 with
// the shipped predicate (`ruleCorpusPairings()`, counting rows carrying neither `unpaired` nor
// `twinless`): **47 of 114** `harvey-*` rules pair on BOTH halves. 0 fail the positive half — that
// half was never affected and stays fatal — and the remaining 67 are twinless, enumerated in
// TWIN_BACKLOG below rather than summarised.
//
// Where a twin IS resolved it proves (a) a benign twin of this rule's own fixture exists in the
// corpus and (b) the rule produced nothing on it. It does NOT prove the twin exercises the specific
// sanitizer the rule implements — a declared rule↔entry link would, and is tracked as follow-up
// work. A rule that fires on many fixtures has many candidate twins, so the (a) half is weakest
// exactly where the rule is broadest.

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

// #1676 — `.npmrc` WAS A UNIVERSAL TWIN, AND 82 OF 114 RULES WERE "PAIRED" AGAINST IT.
//
// `stem` used to be `p.replace(/\.[a-z]+$/i, "")`, which maps a bare dotfile — `.npmrc` — to the
// EMPTY STRING. The candidate filter below asks `p.startsWith(s)`, and every string starts with "",
// so `.npmrc` (tracked under negative N-NPM-TOKEN-ENV's location) was a twin candidate for EVERY
// rule; and since `firedStems` never contains "", it always passed the "the rule stayed silent on
// it" test too. MEASURED 2026-08-01 before the fix: 82 of 114 rules had `.npmrc` as their chosen
// twin, i.e. the negative half of this gate — the whole "and stayed silent on its benign twin"
// claim — was satisfied by the empty string for 72% of the rules it reports on.
//
// The lookbehind keeps a real basename: `lib/jwt.js` → `lib/jwt`, `.npmrc` → `.npmrc`,
// `lib/.npmrc` → `lib/.npmrc`.
//
// EXPORTED FOR ONE REASON, and it is the same defect class this whole comment is about. The guard
// named after this regex — `EMPTY_STEM_IS_A_UNIVERSAL_TWIN` in the test file — used to declare its
// own copy of the pattern, so it was a duplicate of the thing it guarded rather than a test of it.
// MEASURED 2026-08-01: reverting this line to the empty-string form left that test GREEN (1 failed
// / 10 passed, and the one failure was `TWIN_BACKLOG can only shrink`, a different test catching it
// by accident). It now imports THIS binding, so the same reversion reddens the test that claims to
// catch it.
export const stem = (p: string): string => p.replace(/(?<=[^/])\.[a-z]+$/i, "");
const filePart = (location: string): string => location.replace(/^\[source\] /, "").split(":")[0] ?? location;
const BENIGN_SUFFIX = /-(safe|fixed|guarded|scoped|allowlist)$/;

/**
 * #1676 — a unit this gate can pair. `harvey-*` semgrep rules were the only ones until now; the
 * predicate below never depended on that, it is keyed entirely on TAXONOMY, so the AST detectors,
 * the secret scanners, the dependency/licence checks and the third-party packs pair the same way.
 */
interface PairableUnit {
  id: string;
  engine: string;
  taxonomy: string;
}

interface UnitPairing {
  rule: string;
  engine: string;
  positives: string[]; // corpus entry ids a finding from this unit satisfies
  twin?: { entry: string; fixture: string };
  /** POSITIVE half failed: nothing in the corpus would notice this unit dying. Always fatal. */
  unpaired?: string;
  /** NEGATIVE half failed: nothing shows it staying silent on a benign twin. Ratcheted, not fatal. */
  twinless?: string;
}

export function pairUnits(
  units: PairableUnit[],
  findings: Finding[] = committedScanFindings(),
  corpus: CorpusEntry[] = CORPUS,
): UnitPairing[] {
  const tracked = execFileSync("git", ["ls-files", "targets/calibration"], { cwd: repoRoot, encoding: "utf8" })
    .trim().split("\n").map((p) => p.replace(/^targets\/calibration\//, ""));
  const negativeFixtures = corpus
    .filter((e) => e.kind === "negative")
    .flatMap((e) => tracked.filter((p) => p.toLowerCase().includes(e.location.toLowerCase())).map((p) => ({ entry: e.id, fixture: p })));

  return units.map(({ id, engine, taxonomy }) => {
    const own = findings.filter((f) => f.taxonomy === taxonomy);
    const positives = corpus.filter((e) => e.kind === "positive" && scoreEntry(e, own).caughtTier !== undefined).map((e) => e.id);
    if (positives.length === 0) {
      return { rule: id, engine, positives, unpaired: own.length === 0 ? "fires on nothing in targets/calibration — it has never been shown to work" : "fires, but no POSITIVE corpus entry scores it, so nothing would notice if it stopped" };
    }
    const firedStems = new Set(own.map((f) => stem(filePart(f.location))));
    const candidates = negativeFixtures.filter(({ fixture }) => {
      const s = stem(fixture);
      return [...firedStems].some((p) => s.startsWith(`${p}-`) || (s !== p && p.startsWith(s.replace(BENIGN_SUFFIX, ""))));
    });
    if (candidates.length === 0) return { rule: id, engine, positives, twinless: "no benign twin fixture — nothing proves it stays silent on the safe form of what it flags" };
    // A candidate the rule ALSO fired on proves nothing about silence. Several corpus fixtures are
    // shared files carrying both a planted defect and its benign sibling, so this is the normal
    // case, not an error — the rule is unpaired only when EVERY candidate carries one of its hits.
    const twin = candidates.find(({ fixture }) => !firedStems.has(stem(fixture)));
    if (!twin) return { rule: id, engine, positives, twinless: `every benign twin candidate (${candidates.map((c) => c.fixture).join(", ")}) also carries a hit from this rule — nothing shows it staying silent` };
    return { rule: id, engine, positives, twin };
  });
}

export function ruleCorpusPairings(
  rules: SemgrepRule[] = harveySemgrepRules(),
  findings: Finding[] = committedScanFindings(),
  corpus: CorpusEntry[] = CORPUS,
): UnitPairing[] {
  return pairUnits(rules.map((r) => ({ id: r.id, engine: "harvey-semgrep", taxonomy: r.taxonomy })), findings, corpus);
}

// #1676 — THE NEGATIVE HALF OF THIS GATE, HELD AS A RATCHET INSTEAD OF A FICTION.
//
// Fixing `stem` above (a bare dotfile no longer collapses to the empty string, so `.npmrc` stopped
// being a universal twin candidate) turned a 0 into a real number. MEASURED 2026-08-01 over
// dry-run/findings.json, both arms on the same commit:
//
//   before the `stem` fix: 114 harvey-* rules, 0 twinless — 82 of them "paired" against `.npmrc`
//   after  the `stem` fix: 114 harvey-* rules, 67 twinless
//   outside-engine units:  19 taxonomies, 8 twinless (and 3 with no scoring positive, below)
//
// So the "and stayed silent on its benign twin" half was satisfied by the empty string for 72% of
// the rules it reported on. The POSITIVE half was never affected and stays fatal: 0 unpaired, both
// before and after.
//
// This list is what remains, enumerated rather than summarised, and it is a RATCHET: a unit not on
// it that becomes twinless FAILS, and a unit on it that gains a real twin fails as STALE. It can
// only shrink. Writing a benign twin fixture for 75 units is the actual remediation and is tracked
// separately — what is NOT acceptable, and what this replaces, is a green gate asserting a silence
// nobody has observed.
export const TWIN_BACKLOG: readonly string[] = [
  "Browser-only sanitizer in a server-rendered component", "GitHub Actions workflow grants write-all token permissions",
  "Migration disables RLS on a public table (static)", "Migration table without RLS (static)", "Role with BYPASSRLS defeats row-level security (static)",
  "Sensitive file in public/ directory", "Unpinned dependency", "harvey-aead-decipher-no-final", "harvey-auth-admin-in-client",
  "harvey-authed-no-role-check", "harvey-body-parser-no-limit", "harvey-code-injection-eval", "harvey-cors-reflected-origin",
  "harvey-cors-reflected-origin-object", "harvey-crypto-createcipher", "harvey-crypto-pseudorandombytes", "harvey-csp-unsafe-inline",
  "harvey-dangerously-allow-browser", "harvey-dangerously-set-inner-html", "harvey-dangerously-set-inner-html-prop",
  "harvey-dangerously-set-inner-html-stored", "harvey-document-write", "harvey-dom-innerhtml", "harvey-dynamic-require",
  "harvey-edgefn-secret-fallback", "harvey-fail-open", "harvey-gcm-no-authtaglength", "harvey-hpp-query-cast", "harvey-href-js-url",
  "harvey-idor-param", "harvey-img-remotepatterns-wild", "harvey-incomplete-sanitize", "harvey-insecure-random-token",
  "harvey-insecure-ws-url", "harvey-internal-state-response", "harvey-jwt-decode-noverify", "harvey-jwt-decode-render",
  "harvey-lib-code-injection", "harvey-lib-command-injection", "harvey-lib-path-traversal", "harvey-log-injection",
  "harvey-mass-assignment-bare", "harvey-missing-frame-options", "harvey-missing-hsts", "harvey-missing-nosniff",
  "harvey-missing-sri", "harvey-nextconfig-env-secret", "harvey-open-url-sink", "harvey-path-traversal", "harvey-pg-ssl-disabled",
  "harvey-plaintext-password", "harvey-postgrest-filter-injection", "harvey-postmessage-no-origin", "harvey-postmessage-wildcard",
  "harvey-prod-sourcemaps", "harvey-prototype-pollution", "harvey-public-bucket", "harvey-redos", "harvey-secret-in-url-param",
  "harvey-sensitive-response-cached", "harvey-server-action-noauth", "harvey-serveractions-origin-wild", "harvey-service-role-in-client",
  "harvey-set-attribute-xss", "harvey-static-iv", "harvey-template-injection", "harvey-token-in-webstorage", "harvey-unsafe-deserialization",
  "harvey-verbose-error", "harvey-vite-service-role-in-client", "harvey-vm-unsafe-sandbox", "harvey-weak-cipher",
  "harvey-weak-hash-security", "harvey-zip-slip", "javascript.node-crypto.security.create-de-cipher-no-iv.create-de-cipher-no-iv",
];

/**
 * #1676 — outside-engine units the corpus emits at free-count tier with NO positive entry scoring
 * them, so nothing would notice if they stopped firing. Three today, each with its own reason
 * rather than one reason wearing three coats. Also a ratchet: a new one fails the gate.
 */
// `unit`, not the obvious field name: a taxonomy string literal under src/scan is harvested by
// src/cwe-map.test.ts as a DETECTOR taxonomy needing a CWE decision, and two of these three name a
// third-party pack rule Harvey does not own.
export const UNSCORED_OUTSIDE_UNITS: readonly { unit: string; engine: string; reason: string }[] = [
  {
    unit: "Committed credential — docs/example context",
    engine: "Harvey TS/AST detectors",
    reason:
      "MEASURED 2026-08-01: this taxonomy is #934's RECLASSIFICATION of a Committed credential found in a docs/example path, and the corpus scores the reclassification through the negative side (mustNotGradeDocContextCreds on carbon, src/scan/external-corpus.ts) rather than through a planted positive. A positive entry here would need a calibration fixture that plants a credential in a docs path AND asserts it stays out of the graded set — the assertion the free-tier expectation already makes on a real 4k-file repo.",
  },
  {
    unit: "javascript.node-crypto.security.aead-no-final.aead-no-final",
    engine: "third-party semgrep packs",
    reason:
      "MEASURED 2026-08-01: a REGISTRY pack rule (p/javascript), not ours. It fires on lib/aead-nofinal.js, the fixture planted for harvey-aead-decipher-no-final, and the corpus positive there is keyed to Harvey's own taxonomy — so the pack rule co-fires and is scored by nothing. Pinning a positive to an upstream rule id makes this repo's gate fail when the pack renames a rule, which is a different failure from the one the gate is for.",
  },
  {
    unit: "yaml.github-actions.security.pull-request-target-code-checkout.pull-request-target-code-checkout",
    engine: "third-party semgrep packs",
    reason:
      "MEASURED 2026-08-01: same shape as the aead one — a p/github-actions pack rule co-firing on the workflow fixture planted for harvey's own GHA checks, scored by no corpus entry of its own.",
  },
];

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
// that stays true. RE-MEASURED 2026-08-01 against dry-run/findings.json, by calling
// `freeCountCoverage()` — 164 high-tier findings, 110 from an enumerated harvey-* rule, 54 (32.9%)
// from something else: committed credentials, the M1 object-level-authz AST detector, static-RLS
// migration checks, dependency and license checks, and two third-party semgrep packs. (The
// 157/104/53 figure recorded here through 2026-07-31 was stale against this same artifact; the
// sibling comment in quick-scan.ts and this one now quote one measurement, not two.)
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
  // #1676: the same population split by ENGINE, so "a third of the free count is ungated" can be
  // read as "WHICH third", and so a new engine appearing in a client's free count is visible rather
  // than absorbed into one percentage. `findings` counts FINDINGS, so the parts sum to
  // `outsidePairingGate` on any input — see the comment at the accumulator below.
  byEngine: { engine: string; findings: number; taxonomies: number }[];
}

export function freeCountCoverage(
  findings: Finding[] = committedScanFindings(),
  rules: SemgrepRule[] = harveySemgrepRules(),
  pairings: UnitPairing[] = ruleCorpusPairings(rules, findings),
): FreeCountCoverage {
  const ruleTaxonomies = new Set(rules.map((r) => r.taxonomy));
  const high = findings.filter((f) => f.precisionTier === "high");
  const outside = high.filter((f) => !ruleTaxonomies.has(f.taxonomy));
  const unpairedRules = new Set(pairings.filter((p) => p.unpaired).map((p) => p.rule));
  const unpairedTaxonomies = new Set(rules.filter((r) => unpairedRules.has(r.id)).map((r) => r.taxonomy));
  // #1676: count FINDINGS, not distinct ids. This accumulator deduplicated by `f.id`, which is
  // invisible on the committed artifact (ids are unique there) and wrong on a live scan: MEASURED
  // 2026-08-01, a live run reported 78 findings outside the gate while the five engine rows summed
  // to 71 — ~7 absorbed by shared ids. This is the client-facing "which share of your free count is
  // ungated" disclosure, so the parts have to sum to the whole; a row that quietly swallows seven
  // findings is the silent-omission shape wearing a breakdown.
  const engines = new Map<string, { findings: number; taxa: Set<string> }>();
  for (const f of outside) {
    const key = engineOfFinding(f);
    const slot = engines.get(key) ?? { findings: 0, taxa: new Set<string>() };
    slot.findings += 1;
    slot.taxa.add(f.taxonomy);
    engines.set(key, slot);
  }
  return {
    highTier: high.length,
    coveredByPairingGate: high.length - outside.length,
    outsidePairingGate: outside.length,
    outsideTaxonomies: [...new Set(outside.map((f) => f.taxonomy))].sort(),
    droppedByPerRuleGate: high.filter((f) => unpairedTaxonomies.has(f.taxonomy)).map((f) => f.id),
    byEngine: [...engines].map(([engine, s]) => ({ engine, findings: s.findings, taxonomies: s.taxa.size })).sort((a, b) => b.findings - a.findings),
  };
}

// #1676 — THE PAIRING-EQUIVALENT GATE FOR THE ENGINES OUTSIDE `harvey-*`.
//
// #1414 measured the hole and stopped there, on the reading that "the AST detector, the secret
// scanners and the dependency checks have different notions of positive and benign twin, and none
// of them is a rule id you can pair against a corpus row". RE-TESTED 2026-08-01 and that is false
// of the predicate as written: `pairUnits` keys on TAXONOMY, never on a rule id or a YAML file, and
// its benign-twin derivation reads calibration FIXTURE NAMES. Nothing in it is semgrep-specific —
// the only semgrep-shaped part was the ENUMERATION, `harveySemgrepRules()` reading `*.yml`.
//
// So the unit here is a taxonomy the committed scan actually emitted at free-count tier from
// something other than an enumerated harvey-* rule, paired by the identical predicate. MEASURED
// 2026-08-01 over dry-run/findings.json: 19 such taxonomies — 8 pair fully, 8 have a scoring
// positive but no benign twin, 3 have no scoring positive at all. The last two groups are
// DISCLOSED (TWIN_BACKLOG / UNSCORED_OUTSIDE_UNITS) rather than fixed here.
const OUTSIDE_ENGINES: { engine: string; id: RegExp }[] = [
  { engine: "secret scanners (gitleaks/trufflehog)", id: /^SEC-(GL|TH)-/ },
  { engine: "dependency / supply-chain / licence checks", id: /^(DEP|SUP)-/ },
  { engine: "static-RLS migration checks", id: /^SB-/ },
  // A bare `SEM-<n>` id outside the harvey-* taxonomy set is a registry pack's rule; `SEM-PUBLIC-1`
  // and friends are Harvey's own detectors and fall through to the default.
  { engine: "third-party semgrep packs", id: /^SEM-\d+$/ },
];

function engineOfFinding(f: Finding): string {
  return OUTSIDE_ENGINES.find((e) => e.id.test(f.id))?.engine ?? "Harvey TS/AST detectors";
}

/** The outside-engine units, derived from what the committed scan actually produced at free-count tier. */
export function freeCountOutsideUnits(
  findings: Finding[] = committedScanFindings(),
  rules: SemgrepRule[] = harveySemgrepRules(),
): PairableUnit[] {
  const ruleTaxonomies = new Set(rules.map((r) => r.taxonomy));
  const seen = new Map<string, PairableUnit>();
  for (const f of findings) {
    if (f.precisionTier !== "high" || ruleTaxonomies.has(f.taxonomy) || seen.has(f.taxonomy)) continue;
    seen.set(f.taxonomy, { id: f.taxonomy, engine: engineOfFinding(f), taxonomy: f.taxonomy });
  }
  return [...seen.values()].sort((a, b) => a.id.localeCompare(b.id));
}
