import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_ROOTS,
  collectReasons,
  issueSources,
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

  it("accepts the blocker once it is decisional and points at the issue the question is recorded on", () => {
    expect(validateRecordedReason(one([BLOCKED, DECISIONAL_KIND, PROVENANCE, OWNER, "DECISION: #1319"]))).toEqual([]);
  });

  // The live false-positive this guard has to survive: src/cli/validate-conservation.test.ts's two
  // reasons name .github/workflows/ci.yml while describing which job runs a file, not citing
  // supervision at all.
  it("leaves a reason that merely mentions a supervised path alone", () => {
    const mentions = "REASON: this block needs HARVEY_CONSERVATION_E2E, which only .github/workflows/conservation.yml sets";
    expect(validateRecordedReason(one([mentions, EMPIRICAL_KIND, PROVENANCE, FALSIFIER]))).toEqual([]);
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
