import { describe, expect, it } from "vitest";
import { intakeDoc, TRACKER_INTAKE, type TrackerKind } from "./scoped-tokens.js";

const KINDS = Object.keys(TRACKER_INTAKE) as TrackerKind[];

describe("scoped-token auth intake (#747)", () => {
  it("documents a least-privilege scope and the env vars for every CLI tracker", () => {
    for (const kind of KINDS) {
      const doc = intakeDoc(kind);
      expect(doc).toContain("Minimum scope:");
      for (const env of TRACKER_INTAKE[kind].envVars) expect(doc).toContain(env);
    }
  });

  it("never echoes a token VALUE — the doc references env-var names only", () => {
    // The intake sheet is static documentation; it takes no secret. Even with a token set in the
    // environment, the doc must carry only the var NAME, never its value (the credentials contract).
    const SECRET = "ghp_SECRET_should_never_appear_0xDEADBEEF";
    const prev = process.env.GITHUB_TOKEN;
    process.env.GITHUB_TOKEN = SECRET;
    try {
      for (const kind of KINDS) expect(intakeDoc(kind)).not.toContain(SECRET);
    } finally {
      if (prev === undefined) delete process.env.GITHUB_TOKEN;
      else process.env.GITHUB_TOKEN = prev;
    }
  });
});
