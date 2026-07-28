import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CLAIM_BASELINE } from "./unstructured-claims-baseline.js";
import {
  DEFAULT_ROOTS,
  claimCensusByFile,
  claimCounts,
  claimRatchetBreaches,
  claimTotal,
  collectReasons,
  censusScope,
  collectSources,
  issueSources,
  markNewClaims,
  parseRecordedReasons,
  reasonKind,
  revalidateReasons,
  subsystemDrift,
  untriagedClaims,
  validateRecordedReason,
  watchedPaths,
  type ParsedReason,
} from "./recorded-reasons.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const reasonsForCensus = collectReasons(DEFAULT_ROOTS, REPO_ROOT);

const CLAIM = "REASON: the shared source loader does not read .svelte/.vue/.astro";
const EMPIRICAL_KIND = "KIND: empirical";
const DECISIONAL_KIND = "KIND: decisional";
const PROVENANCE = "PROVENANCE: MEASURED 2026-07-25";
const FALSIFIER = 'FALSIFIER: grep -Eq "svelte" src/detectors/load-sources.ts';
const OWNER = "OWNER: operator";
const DECISION = "DECISION: docs/design/infrastructure-out-of-scope.md (#886)";

const FALSIFIER_TIER = "FALSIFIER-TIER: lighthouse";

const EMPIRICAL = [CLAIM, EMPIRICAL_KIND, PROVENANCE, FALSIFIER];
const DECISIONAL = [CLAIM, DECISIONAL_KIND, PROVENANCE, OWNER, DECISION];
const LIVE_EMPIRICAL = [CLAIM, EMPIRICAL_KIND, PROVENANCE, FALSIFIER, FALSIFIER_TIER];

const block = (lines: string[], prefix = "// ") => lines.map((l) => prefix + l).join("\n");

function one(lines: string[], prefix?: string): ParsedReason {
  const [first] = parseRecordedReasons(block(lines, prefix), "f.ts");
  if (!first) throw new Error("no reason block parsed");
  return first;
}

const statuses = (rows: { status: string }[]) => rows.map((r) => r.status);

describe("parseRecordedReasons", () => {
  it("reads a block out of a TS comment, a Markdown quote and an HTML comment alike", () => {
    for (const prefix of ["// ", "> ", "<!-- ", "  * ", "| "]) {
      expect(one(EMPIRICAL, prefix).fields.KIND).toBe("empirical");
    }
  });

  it("closes a block at a blank line so following prose is never absorbed", () => {
    const reasons = parseRecordedReasons(`${block(EMPIRICAL)}\n\n// OWNER: nobody\n`, "f.ts");
    expect(reasons).toHaveLength(1);
    expect(reasons[0]?.fields.OWNER).toBeUndefined();
  });

  it("reports a mistyped field rather than dropping it — a silently ignored FALSIFER: is a reason with no falsifier", () => {
    const r = one([CLAIM, EMPIRICAL_KIND, PROVENANCE, "FALSIFER: grep -q x src/"]);
    expect(r.parseErrors.join()).toContain("unknown field FALSIFER");
    expect(validateRecordedReason(r).join()).toContain("FALSIFIER: missing");
  });

  it("ignores a fenced Markdown block — documenting the convention is not recording a reason", () => {
    const md = `text\n\`\`\`\n${EMPIRICAL.join("\n")}\n\`\`\`\n`;
    expect(parseRecordedReasons(md, "doc.md")).toEqual([]);
    expect(parseRecordedReasons(md, "code.ts")).toHaveLength(1);
  });

  it("starts a new block on a second REASON: without swallowing the first", () => {
    expect(parseRecordedReasons(`${block(EMPIRICAL)}\n${block(DECISIONAL)}`, "f.ts")).toHaveLength(2);
  });
});

describe("validateRecordedReason — the empirical/decisional split is structural", () => {
  it("accepts a well-formed reason of either kind", () => {
    expect(validateRecordedReason(one(EMPIRICAL))).toEqual([]);
    expect(validateRecordedReason(one(DECISIONAL))).toEqual([]);
  });

  it("rejects an empirical reason with no falsifier — that is what makes a claim permanent", () => {
    expect(validateRecordedReason(one([CLAIM, EMPIRICAL_KIND, PROVENANCE])).join()).toContain("unfalsifiable and therefore permanent");
  });

  it("rejects a placeholder falsifier, which would satisfy the gate while re-testing nothing", () => {
    expect(validateRecordedReason(one([CLAIM, EMPIRICAL_KIND, PROVENANCE, "FALSIFIER: TBD"])).join()).toContain("placeholder");
  });

  it("REFUSES a falsifier on a decisional reason — re-running a command against a human ruling is a category error", () => {
    expect(validateRecordedReason(one([...DECISIONAL, FALSIFIER])).join()).toContain("refused on a decisional reason");
  });

  it("requires an owner and a decision record on a decisional reason", () => {
    const errors = validateRecordedReason(one([CLAIM, DECISIONAL_KIND, PROVENANCE])).join();
    expect(errors).toContain("OWNER: missing");
    expect(errors).toContain("DECISION: missing");
  });

  it("requires a dated MEASURED/TRIED/ASSUMED tag — an undated claim cannot be aged", () => {
    expect(validateRecordedReason(one([CLAIM, EMPIRICAL_KIND, "PROVENANCE: measured recently", FALSIFIER])).join()).toContain("MEASURED|TRIED|ASSUMED YYYY-MM-DD");
  });

  it("requires the kind to be declared at all", () => {
    expect(validateRecordedReason(one([CLAIM, PROVENANCE, FALSIFIER])).join()).toContain("KIND: must be");
  });

  it("accepts a live-only empirical reason whose FALSIFIER-TIER names a registered tier (#1072)", () => {
    expect(validateRecordedReason(one(LIVE_EMPIRICAL))).toEqual([]);
  });

  it("rejects a FALSIFIER-TIER outside the registered set — a typo would make the falsifier silently always-skipped", () => {
    expect(validateRecordedReason(one([CLAIM, EMPIRICAL_KIND, PROVENANCE, FALSIFIER, "FALSIFIER-TIER: not-a-tier"])).join()).toContain("not a registered live tier");
  });

  it("REFUSES FALSIFIER-TIER on a decisional reason — it qualifies a FALSIFIER the reason must not carry", () => {
    expect(validateRecordedReason(one([...DECISIONAL, FALSIFIER_TIER])).join()).toContain("FALSIFIER-TIER: refused on a decisional reason");
  });

  it("rejects a <placeholder> in an offline falsifier — the shell reads it as a redirect, so it can never exit 0 (#1072)", () => {
    const errors = validateRecordedReason(one([CLAIM, EMPIRICAL_KIND, PROVENANCE, "FALSIFIER: pnpm quick-scan --dir <some-clone> | grep -q csrf"])).join();
    expect(errors).toContain("HARVEY_FALSIFIER_SOME_CLONE");
    expect(errors).toContain("input redirect");
  });

  it("allows a <placeholder> once the reason declares the tier that supplies it", () => {
    expect(validateRecordedReason(one([CLAIM, EMPIRICAL_KIND, PROVENANCE, "FALSIFIER: pnpm quick-scan --dir <some-clone>", FALSIFIER_TIER]))).toEqual([]);
  });

  it("does not mistake shell syntax for a placeholder", () => {
    expect(validateRecordedReason(one([CLAIM, EMPIRICAL_KIND, PROVENANCE, "FALSIFIER: grep -q x src/a.ts < /dev/null 2>&1"]))).toEqual([]);
  });
});

// #1319 — the four falsified claims (#951, #957, #52, #873) were all impossibility assertions over
// an untested basis. PROVENANCE already records whether anyone looked, so the rule is checkable.
describe("a budget limit must not borrow impossibility's vocabulary (#1319)", () => {
  const IMPOSSIBLE = "REASON: a full pull of the stack is out of reach for this pass";
  const ASSUMED = "PROVENANCE: ASSUMED 2026-07-27";

  it("REFUSES impossibility vocabulary on a reason nobody tested", () => {
    const errors = validateRecordedReason(one([IMPOSSIBLE, EMPIRICAL_KIND, ASSUMED, FALSIFIER])).join();
    expect(errors).toContain('says "out of reach" on an ASSUMED provenance');
    expect(errors).toContain("ask it as a question");
  });

  it("catches it on a decisional reason too — the register is the defect, not the kind", () => {
    expect(validateRecordedReason(one([IMPOSSIBLE, DECISIONAL_KIND, ASSUMED, OWNER, DECISION])).join()).toContain("#1319");
  });

  it("accepts the same claim once someone has gone and looked", () => {
    expect(validateRecordedReason(one([IMPOSSIBLE, EMPIRICAL_KIND, PROVENANCE, FALSIFIER]))).toEqual([]);
  });

  it("accepts an untested reason that names the real constraint instead of asserting the world forbids it", () => {
    const budget = "REASON: not attempted this round — the pull is ~20s and the stand-up is documented in docs/design/m7-chrome-provisioning.md";
    expect(validateRecordedReason(one([budget, EMPIRICAL_KIND, ASSUMED, FALSIFIER]))).toEqual([]);
  });
});

// #1319 — "that path is supervised" silently terminated acceptance criteria in #945/#1056/#472/#381,
// while no executor has ever recorded being refused. Supervision awaits a human, so it is decisional,
// and the DECISION must say where the human was asked.
describe("a supervised path produces a relay, not a silent close (#1319)", () => {
  const BLOCKED = "REASON: the CI wiring is not done because .github/workflows/ is supervised and needs operator approval";

  it("REFUSES the blocker as empirical — no command re-tests whether the operator approved", () => {
    expect(validateRecordedReason(one([BLOCKED, EMPIRICAL_KIND, PROVENANCE, FALSIFIER])).join()).toContain("produces a RELAY, never a silent stop");
  });

  it("REFUSES a DECISION that names no venue — a relay nobody can find is the silent close", () => {
    expect(validateRecordedReason(one([BLOCKED, DECISIONAL_KIND, PROVENANCE, OWNER, "DECISION: asked the operator"])).join()).toContain("names no venue");
  });

  // The venue rule first shipped as /#\d+|\//, where any slash at all counted — so "pending a
  // go/no-go" satisfied it, which is precisely the relay-with-no-venue the rule exists to refuse.
  it("REFUSES a DECISION whose only path-like token is a slash inside a word", () => {
    expect(validateRecordedReason(one([BLOCKED, DECISIONAL_KIND, PROVENANCE, OWNER, "DECISION: pending a go/no-go"])).join()).toContain("names no venue");
  });

  it("accepts the blocker once it is decisional and points at the issue the question is recorded on", () => {
    expect(validateRecordedReason(one([BLOCKED, DECISIONAL_KIND, PROVENANCE, OWNER, "DECISION: #1319"]))).toEqual([]);
  });

  it("accepts a decision-record path as the venue too", () => {
    expect(validateRecordedReason(one([BLOCKED, DECISIONAL_KIND, PROVENANCE, OWNER, "DECISION: docs/design/recorded-reasons.md"]))).toEqual([]);
  });

  // The live false-positive this guard has to survive: src/cli/validate-conservation.test.ts's two
  // reasons name .github/workflows/ci.yml while describing which job runs a file, not citing
  // supervision at all.
  it("leaves a reason that merely mentions a supervised path alone", () => {
    const mentions = "REASON: this block needs HARVEY_CONSERVATION_E2E, which only .github/workflows/conservation.yml sets";
    expect(validateRecordedReason(one([mentions, EMPIRICAL_KIND, PROVENANCE, FALSIFIER]))).toEqual([]);
  });

  // The harder half, and the one the first cut of this check got wrong: supervision vocabulary and a
  // supervised path BOTH present, one clause apart, with the path cited as a reference rather than
  // named as the blocker. Co-occurrence cannot tell this from BLOCKED above.
  it("leaves a supervised path CITED as the record of a ruling alone, supervision vocabulary and all", () => {
    const cites = "REASON: the source loader does not read .svelte files; the scope rationale and the operator ruling behind it are recorded in docs/design/infrastructure-out-of-scope.md";
    expect(validateRecordedReason(one([cites, EMPIRICAL_KIND, PROVENANCE, FALSIFIER]))).toEqual([]);
  });

  it("still fires when the blocker names a file inside the supervised directory", () => {
    const named = "REASON: the CI wiring is not done because the .github/workflows/ci.yml job is supervised";
    expect(validateRecordedReason(one([named, EMPIRICAL_KIND, PROVENANCE, FALSIFIER])).join()).toContain("produces a RELAY, never a silent stop");
  });
});

describe("revalidateReasons — seeded proof that the gate fires on a reason whose blocker is gone", () => {
  it("flags a reason STALE when its falsifier now exits 0", () => {
    const rows = revalidateReasons([one(EMPIRICAL)], () => ({ code: 0, output: "src/detectors/load-sources.ts" }));
    expect(statuses(rows)).toEqual(["STALE"]);
    expect(rows[0]?.detail).toContain("the blocker is GONE");
  });

  it("leaves a reason alone while its falsifier still exits non-zero", () => {
    expect(statuses(revalidateReasons([one(EMPIRICAL)], () => ({ code: 1, output: "" })))).toEqual(["holds"]);
  });

  it("calls out a falsifier that could not run instead of reading its non-zero exit as 'still blocked'", () => {
    expect(statuses(revalidateReasons([one(EMPIRICAL)], () => ({ code: 127, output: "sh: grrep: not found" })))).toEqual(["UNVERIFIABLE"]);
    expect(statuses(revalidateReasons([one(EMPIRICAL)], () => ({ code: null, output: "" })))).toEqual(["UNVERIFIABLE"]);
  });

  it("never runs a command for a decisional reason", () => {
    const rows = revalidateReasons([one(DECISIONAL)], () => {
      throw new Error("a decisional reason must not be re-tested by command");
    });
    expect(rows).toEqual([]);
  });

  it("SKIPS a live-only falsifier when its tier is unavailable — disclosed and counted, never run (#1072)", () => {
    const rows = revalidateReasons([one(LIVE_EMPIRICAL)], () => {
      throw new Error("a live-only falsifier must not run when its tier is unavailable");
    });
    expect(statuses(rows)).toEqual(["SKIPPED-LIVE"]);
    expect(rows[0]?.detail).toContain("lighthouse");
  });

  it("runs a live-only falsifier once its tier is declared available, and reads its exit like any other", () => {
    const available = new Set(["lighthouse"]);
    expect(statuses(revalidateReasons([one(LIVE_EMPIRICAL)], () => ({ code: 1, output: "" }), available))).toEqual(["holds"]);
    expect(statuses(revalidateReasons([one(LIVE_EMPIRICAL)], () => ({ code: 0, output: "" }), available))).toEqual(["STALE"]);
  });

  describe("<placeholder> bindings on a live-tier falsifier (#1072)", () => {
    const PLACEHOLDER_FALSIFIER = [CLAIM, EMPIRICAL_KIND, PROVENANCE, "FALSIFIER: pnpm quick-scan --dir <some-clone> | grep -q csrf", FALSIFIER_TIER];
    const available = new Set(["lighthouse"]);

    it("refuses to run an unbound placeholder — executing it verbatim exits non-zero and reads as 'the blocker holds'", () => {
      const rows = revalidateReasons([one(PLACEHOLDER_FALSIFIER)], () => {
        throw new Error("an unbound placeholder must not reach the shell");
      }, available);
      expect(statuses(rows)).toEqual(["UNVERIFIABLE"]);
      expect(rows[0]?.detail).toContain("HARVEY_FALSIFIER_SOME_CLONE");
    });

    it("substitutes the binding and runs the resolved command", () => {
      let ran = "";
      const rows = revalidateReasons([one(PLACEHOLDER_FALSIFIER)], (c) => {
        ran = c;
        return { code: 1, output: "" };
      }, available, () => "/clones/superredhat");
      expect(ran).toBe("pnpm quick-scan --dir /clones/superredhat | grep -q csrf");
      expect(statuses(rows)).toEqual(["holds"]);
    });

    it("names the bindings the live run will need when the tier is unavailable", () => {
      const rows = revalidateReasons([one(PLACEHOLDER_FALSIFIER)], () => ({ code: 1, output: "" }));
      expect(statuses(rows)).toEqual(["SKIPPED-LIVE"]);
      expect(rows[0]?.detail).toContain("HARVEY_FALSIFIER_SOME_CLONE");
    });
  });
});

describe("subsystemDrift — catches the #1035 shape without re-running anything", () => {
  const withTouches = one([...EMPIRICAL, "TOUCHES: src/detectors/load-sources.ts"]);

  it("reports a reason whose referenced subsystem moved after the reason was recorded", () => {
    const rows = subsystemDrift([withTouches], () => ["abc1234", "def5678"]);
    expect(rows[0]?.detail).toContain("2 commit(s) landed on src/detectors/load-sources.ts");
  });

  it("stays quiet when the subsystem has not moved", () => {
    expect(subsystemDrift([withTouches], () => [])).toEqual([]);
  });

  // #1246 — the alternative was making TOUCHES mandatory, which would fail the three planted
  // negative controls in reasons-drift.yml structurally and stop them proving anything.
  it("watches a reason that declared no TOUCHES, by deriving the paths its falsifier names", () => {
    const rows = subsystemDrift([one(EMPIRICAL)], () => ["abc1234"], (p) => p === "src/detectors/load-sources.ts");
    expect(rows[0]?.detail).toContain("src/detectors/load-sources.ts");
  });
});

describe("watchedPaths — declared TOUCHES plus whatever the falsifier already names (#1246)", () => {
  const all = () => true;

  it("keeps only tokens that exist here, so a <placeholder> and a /tmp scratch path drop out", () => {
    const r = one([CLAIM, EMPIRICAL_KIND, PROVENANCE, "FALSIFIER: pnpm quick-scan --dir <clone> --out /tmp/x.json && grep -q y src/scan/leftover-auth.ts", FALSIFIER_TIER]);
    expect(watchedPaths(r, (p) => p === "src/scan/leftover-auth.ts")).toEqual(["src/scan/leftover-auth.ts"]);
  });

  it("ignores node_modules — a path outside this repo's history can only ever report zero commits", () => {
    expect(watchedPaths(one([CLAIM, EMPIRICAL_KIND, PROVENANCE, "FALSIFIER: test -d node_modules/vitest/dist"]), all)).toEqual([]);
  });

  it("unions the declared paths with the derived ones rather than letting either win", () => {
    const r = one([...EMPIRICAL, "TOUCHES: docs/design/m6-simplification-eval.md"]);
    expect(watchedPaths(r, all).sort()).toEqual(["docs/design/m6-simplification-eval.md", "src/detectors/load-sources.ts"]);
  });

  it("rejects a declared path that is not in the checkout — git log on a typo is silent forever", () => {
    const r = one([...EMPIRICAL, "TOUCHES: src/detectors/loadsources.ts"]);
    expect(validateRecordedReason(r, () => false).join()).toContain("is not a path in this checkout");
  });
});

describe("untriagedClaims — the claims outside every block, counted rather than assumed clean (#1246)", () => {
  const source = (text: string) => [{ file: "doc.md", text }];

  it("counts a standing claim that no block covers", () => {
    const rows = untriagedClaims(source("M6 cannot be scored by the corpus.\n"), []);
    expect(rows).toEqual([{ file: "doc.md", line: 1, text: "M6 cannot be scored by the corpus." }]);
  });

  it("does not re-count a claim that has already been triaged into a block", () => {
    const text = `${block(EMPIRICAL, "")}\n`;
    expect(untriagedClaims([{ file: "doc.md", text }], parseRecordedReasons(text, "doc.md"))).toEqual([]);
  });

  it("skips fenced code — a sample command is not a claim about the world", () => {
    expect(untriagedClaims(source("```\ngrep -q 'cannot' x\n```\n"), [])).toEqual([]);
  });
});

describe("issueSources — a claim recorded outside the repo is still a claim (#1246)", () => {
  it("renders the body and each comment as its own addressable surface", () => {
    const sources = issueSources([{ number: 920, body: "b", comments: [{ body: "c1" }, { body: "c2" }] }]);
    expect(sources.map((s) => s.file)).toEqual(["issue #920", "issue #920 (comment 1)", "issue #920 (comment 2)"]);
  });
});

describe("the repo's own recorded reasons (the gate `pnpm verify` enforces)", () => {
  const reasons = collectReasons(DEFAULT_ROOTS, REPO_ROOT);

  // The exists predicate is real here on purpose: a TOUCHES: path that does not resolve makes the
  // subsystem-drift half permanently silent for that reason, which no structural check would see.
  it("are all well-formed, and every path they claim to watch resolves", () => {
    const bad = reasons
      .map((r) => ({ at: `${r.file}:${r.line}`, errors: validateRecordedReason(r, (p) => existsSync(resolve(REPO_ROOT, p))) }))
      .filter((x) => x.errors.length > 0);
    expect(bad).toEqual([]);
  });

  // A gate scoring an empty set passes forever and proves nothing — the same failure #345 recorded
  // as `requires-live-run: 0`. Both kinds must be present or the split is untested in the wild.
  it("include real reasons of both kinds, so this gate cannot pass vacuously", () => {
    expect(reasons.filter((r) => reasonKind(r) === "empirical").length).toBeGreaterThan(0);
    expect(reasons.filter((r) => reasonKind(r) === "decisional").length).toBeGreaterThan(0);
  });
});

describe("the claim ratchet (#1318) — the census may fall, never rise", () => {
  it("passes when every file is at or under its baseline", () => {
    expect(claimRatchetBreaches({ "a.md": 3, "b.md": 1 }, { "a.md": 3, "b.md": 0 })).toEqual([]);
  });

  // The negative control. A per-file baseline is the point: a single global total is satisfied by
  // deleting a claim here and adding one there, leaving the population untouched.
  it("fails on one added claim line, and on a swap that leaves the total unchanged", () => {
    expect(claimRatchetBreaches({ "a.md": 3 }, { "a.md": 4 })).toEqual([{ file: "a.md", baseline: 3, now: 4 }]);
    expect(claimRatchetBreaches({ "a.md": 3, "b.md": 1 }, { "a.md": 2, "b.md": 2 })).toEqual([{ file: "b.md", baseline: 1, now: 2 }]);
  });

  it("gives a file absent from the baseline a budget of zero, so a new doc full of claims breaches", () => {
    expect(claimRatchetBreaches({}, { "new.md": 2 })).toEqual([{ file: "new.md", baseline: 0, now: 2 }]);
  });

  // End-to-end over the real repo with a real claim-shaped line planted, rather than over a hand-
  // built census: proves the vocabulary, the census and the ratchet are actually wired to each other.
  // toContainEqual, not toEqual: scored against the WHOLE breach list this reddens for any unrelated
  // breach elsewhere in the repo, which is how it and the row below failed together in run
  // 30313783920 and named neither cause. A control has to isolate the rule it names.
  it("fires when a claim-shaped comment is planted in a real repo file", () => {
    const sources = collectSources(DEFAULT_ROOTS, REPO_ROOT);
    const planted = sources.map((s) => (s.file === "CLAUDE.md" ? { ...s, text: `${s.text}\nThis cannot be measured by any existing tier.\n` } : s));
    const census = claimCensusByFile(untriagedClaims(planted, reasonsForCensus).filter((c) => !c.file.startsWith("issue #")));
    const budget = CLAIM_BASELINE["CLAUDE.md"]?.length ?? 0;
    expect(claimRatchetBreaches(claimCounts(CLAIM_BASELINE), census)).toContainEqual({ file: "CLAUDE.md", baseline: budget, now: budget + 1 });
  });

  // #1347's fourth criterion, and the half the .md control above cannot speak to: the ratchet gated
  // prose only, so a claim planted in a source COMMENT moved nothing. Planted in a real `.ts` file
  // under the real vocabulary, and scored against the whole breach list so only this file goes red.
  it("fires when a claim-shaped comment is planted in a real .ts file", () => {
    const target = "src/alert-paths.ts";
    const sources = collectSources(DEFAULT_ROOTS, REPO_ROOT);
    const planted = sources.map((s) => (s.file === target ? { ...s, text: `${s.text}\n// A planted claim: this cannot be measured by any existing tier.\n` } : s));
    const census = claimCensusByFile(untriagedClaims(planted, reasonsForCensus).filter((c) => !c.file.startsWith("issue #")));
    const budget = CLAIM_BASELINE[target]?.length ?? 0;
    expect(claimRatchetBreaches(claimCounts(CLAIM_BASELINE), census)).toContainEqual({ file: target, baseline: budget, now: budget + 1 });
  });

  // The scale trap #1347 asks to decide first: `.ts` carries 767 claim-shaped lines to `.md`'s 274,
  // but 270 of them are error-message strings and test titles. Pinned by an example of each so a
  // widening to whole-file `.ts` cannot happen quietly.
  it("reads a .ts comment but not a .ts code line, so ordinary code prose is not ratcheted", () => {
    const text = ['// this cannot be measured today', 'throw new Error("cannot seed: nothing to drop");'].join("\n");
    expect(untriagedClaims([{ file: "src/x.ts", text }], []).map((c) => c.line)).toEqual([1]);
    expect(untriagedClaims([{ file: "docs/x.md", text }], []).map((c) => c.line)).toEqual([1, 2]);
  });

  it("holds the committed baseline over this repo right now", () => {
    const sources = collectSources(DEFAULT_ROOTS, REPO_ROOT);
    const census = claimCensusByFile(untriagedClaims(sources, reasonsForCensus).filter((c) => !c.file.startsWith("issue #")));
    expect(claimRatchetBreaches(claimCounts(CLAIM_BASELINE), census)).toEqual([]);
    // A baseline that drifted to zero would pass the line above forever while measuring nothing.
    expect(claimTotal(claimCounts(CLAIM_BASELINE))).toBeGreaterThan(100);
  });

  // #1318's third criterion. A breach that reprints every claim in the file is the guessing game it
  // names: on docs/design/recorded-reasons.md (baseline 18) that is nineteen lines, one of them new.
  describe("markNewClaims — the breach names the NEW lines, not every line in the file", () => {
    const at = (line: number, text: string) => ({ file: "d.md", line, text });

    it("marks only the line the baseline does not account for", () => {
      const marked = markNewClaims(["old one", "old two"], [at(1, "old one"), at(2, "old two"), at(3, "brand new")]);
      expect(marked.filter((m) => m.isNew).map((m) => m.claim.line)).toEqual([3]);
    });

    // A count baseline cannot do this: two identical claims and one recorded entry is still a breach,
    // and the second occurrence is the new one.
    it("matches as a multiset, so a claim written twice needs two baseline entries", () => {
      const marked = markNewClaims(["same claim"], [at(1, "same claim"), at(9, "same claim")]);
      expect(marked.map((m) => m.isNew)).toEqual([false, true]);
    });

    it("marks everything new for a file absent from the baseline — a new doc has a budget of zero", () => {
      expect(markNewClaims([], [at(1, "a"), at(2, "b")]).every((m) => m.isNew)).toBe(true);
    });

    // The guarantee the CLI leans on: whenever the count breaches, at least (now - baseline) lines
    // come back new, so a breach can never print an empty list and leave nothing to act on.
    it("never returns an empty set while the count is over budget", () => {
      const baseline = ["a", "b", "c"];
      const current = [at(1, "a"), at(2, "b"), at(3, "c"), at(4, "d")];
      expect(markNewClaims(baseline, current).filter((m) => m.isNew).length).toBeGreaterThanOrEqual(current.length - baseline.length);
    });
  });

  // The boundary itself, asserted rather than left implicit — #1347 existed precisely because it was
  // implicit, and a narrowing that forgets the disclosure would otherwise pass silently.
  it("reads prose whole, code as comments, and refuses to census the generated baseline (#1347)", () => {
    expect(censusScope("docs/design/x.md")).toBe("prose");
    expect(censusScope("briefs/fp-rules.txt")).toBe("prose");
    expect(censusScope("issue #1347")).toBe("prose");
    expect(censusScope("src/alert-paths.ts")).toBe("comments");
    expect(censusScope("src/scan/rules/semgrep/auth.yml")).toBe("comments");
    // Its rows quote every claim in the repo verbatim, so censusing it counts each claim twice.
    expect(censusScope("src/unstructured-claims-baseline.ts")).toBe("none");
  });

  // The three sites #1311 records. They are the population #1318 was built for and none of them was
  // reachable: "untestable" was not in the vocabulary and `.ts` was not censused.
  it("reaches #1311's three `untestable in CI` comments (#1347)", () => {
    const sources = collectSources(DEFAULT_ROOTS, REPO_ROOT);
    const found = untriagedClaims(sources, reasonsForCensus).filter((c) => /untestable in CI/.test(c.text));
    expect(found.map((c) => c.file).sort()).toEqual(["src/audit-runners.ts", "src/audit-runners.ts", "src/pentest/targets.ts"]);
  });
});
