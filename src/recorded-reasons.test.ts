import { describe, expect, it } from "vitest";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_ROOTS,
  collectReasons,
  parseRecordedReasons,
  reasonKind,
  revalidateReasons,
  subsystemDrift,
  validateRecordedReason,
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
});

describe("the repo's own recorded reasons (the gate `pnpm verify` enforces)", () => {
  const reasons = collectReasons(DEFAULT_ROOTS, REPO_ROOT);

  it("are all well-formed", () => {
    const bad = reasons.map((r) => ({ at: `${r.file}:${r.line}`, errors: validateRecordedReason(r) })).filter((x) => x.errors.length > 0);
    expect(bad).toEqual([]);
  });

  // A gate scoring an empty set passes forever and proves nothing — the same failure #345 recorded
  // as `requires-live-run: 0`. Both kinds must be present or the split is untested in the wild.
  it("include real reasons of both kinds, so this gate cannot pass vacuously", () => {
    expect(reasons.filter((r) => reasonKind(r) === "empirical").length).toBeGreaterThan(0);
    expect(reasons.filter((r) => reasonKind(r) === "decisional").length).toBeGreaterThan(0);
  });
});
