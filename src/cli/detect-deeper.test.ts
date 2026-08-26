// #1364: proves detect-deeper's --findings-out format is the one `pnpm record-pass --findings`
// reads, and that the resulting M1 (live) pass round-trips through the #416 read side exactly like
// the existing semantic-pass round trip in audit-pass-artifact.test.ts — the write step this file
// covers (--findings-out) and the write step record-pass.ts covers are already unit-tested
// separately; this proves the two shapes actually fit together end to end.
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import { buildPassArtifact, findFreshPass, ranFromPass, writePassArtifact } from "../audit-pass-artifact.js";
import type { RunContext } from "../audit-runner.js";
import { definerFindings } from "../definer-classifier.js";

describe("detect-deeper --findings-out → record-pass → M1 (live) round trip (#1364)", () => {
  const dir = mkdtempSync(join(tmpdir(), "harvey-detect-deeper-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("writes the same bare Finding[] shape record-pass --findings expects, and it derives ran", () => {
    // What runDetectDeeper's `findings` array actually contains — real classifier output, not a
    // hand-shaped stub, so this exercises the real M1-live finding schema.
    const findings = definerFindings([
      { function: "public.read_row", verdict: "flag", reason: "no auth check on the id parameter", exposedTo: ["authenticated"] },
    ]);
    expect(findings).toHaveLength(1);

    // --findings-out's write (mirrors src/cli/detect-deeper.ts's `writeFileSync(findingsOutPath, ...)`).
    const findingsOutPath = join(dir, "m1-live-findings.json");
    writeFileSync(findingsOutPath, `${JSON.stringify(findings, null, 2)}\n`);

    // record-pass.ts's read of --findings: JSON.parse + Array.isArray, nothing else.
    const parsed = JSON.parse(readFileSync(findingsOutPath, "utf8"));
    expect(Array.isArray(parsed)).toBe(true);

    // record-pass.ts's write (buildPassArtifact + writePassArtifact) with the M1-live pass name.
    const artifact = buildPassArtifact({ module: "M1", target: "/engagement/target", pass: "live", generatedAt: "2026-07-27T00:00:00Z", findings: parsed });
    writePassArtifact(dir, artifact);
    expect(existsSync(join(dir, "M1.pass.json"))).toBe(true);

    // The #416 read side derives ran with the findings intact.
    const ctx: RunContext = {
      targetDir: "/engagement/target",
      env: { connected: true, dynamic: false, llm: false },
      exec: () => ({ ok: true, output: "" }),
      exists: (p) => existsSync(p),
      artifactsDir: dir,
      readArtifact: (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : undefined),
      now: Date.parse("2026-07-27T12:00:00Z"),
    };
    // Keep both readers on the fixture clock even after the real calendar has moved on.
    const wallClock = vi.spyOn(Date, "now").mockReturnValue(Date.parse("2100-01-01T00:00:00Z"));
    try {
      const fresh = findFreshPass(ctx, "M1");
      expect(fresh.fresh).toBe(true);
      if (fresh.fresh) {
        expect(fresh.artifact.pass).toBe("live");
        const ran = ranFromPass(fresh.artifact, "mech", ctx.now);
        expect(ran.status).toBe("ran");
        expect(ran.findings).toEqual(findings);

        // Negative control: the production default still rejects stale findings.
        const staleDefault = ranFromPass(fresh.artifact, "mech");
        expect(staleDefault.findings).toBeUndefined();
        expect(staleDefault.detail).toContain("stale and therefore NOT collected");
      }
    } finally {
      wallClock.mockRestore();
    }
  });
});
