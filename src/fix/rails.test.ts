import { describe, expect, it } from "vitest";
import type { BlastRadius } from "./plan.js";
import {
  checkBlastRadius,
  checkDiffCap,
  checkPath,
  checkPushRef,
  isAllowed,
  isDenied,
  isProtectedBranch,
} from "./rails.js";

function blast(overrides: Partial<BlastRadius> = {}): BlastRadius {
  return {
    files: ["apps/main/src/a.ts"],
    createdFiles: [],
    symbols: [],
    callers: [],
    behaviorPreserving: true,
    estimatedChangedLines: 20,
    ...overrides,
  };
}

describe("isDenied", () => {
  it("denies secrets, env, keys, CI, and git internals", () => {
    for (const p of [
      ".env",
      ".env.local",
      "config/.env.production",
      "app/secrets/keys.ts",
      "certs/server.pem",
      "auth/private.key",
      "src/credentials.json",
      ".github/workflows/ci.yml",
      ".git/config",
    ]) {
      expect(isDenied(p), p).toBe(true);
    }
  });

  it("allows ordinary source files", () => {
    for (const p of ["apps/main/src/actions/save.ts", "src/lib/env-config.ts"]) {
      expect(isDenied(p), p).toBe(false);
    }
  });
});

describe("isAllowed", () => {
  it("matches ** across directories but * only within a segment", () => {
    expect(isAllowed("apps/main/src/deep/nested/x.ts", ["apps/main/src/**"])).toBe(true);
    expect(isAllowed("src/a.ts", ["src/*.ts"])).toBe(true);
    expect(isAllowed("src/a/b.ts", ["src/*.ts"])).toBe(false);
    expect(isAllowed("packages/other/x.ts", ["apps/main/src/**"])).toBe(false);
  });
});

describe("checkPath", () => {
  it("lets the denylist win even when the path is inside the allowlist", () => {
    const r = checkPath(".env", ["**"]);
    expect(r.ok).toBe(false);
    expect(r.violation).toContain("denylisted");
  });

  it("rejects a write outside the allowlist", () => {
    expect(checkPath("packages/other/x.ts", ["apps/main/src/**"]).ok).toBe(false);
  });

  it("permits an allowlisted, non-denied write", () => {
    expect(checkPath("apps/main/src/a.ts", ["apps/main/src/**"]).ok).toBe(true);
  });
});

describe("branch rails", () => {
  it("only permits harvey/fix/* push refs", () => {
    expect(checkPushRef("harvey/fix/F-1").ok).toBe(true);
    expect(checkPushRef("main").ok).toBe(false);
    expect(checkPushRef("feature/x").ok).toBe(false);
  });

  it("treats main/master (plus extras) as protected", () => {
    expect(isProtectedBranch("main")).toBe(true);
    expect(isProtectedBranch("master")).toBe(true);
    expect(isProtectedBranch("release", ["release"])).toBe(true);
    expect(isProtectedBranch("harvey/fix/F-1")).toBe(false);
  });
});

describe("diff cap", () => {
  it("fails when file or line counts exceed the cap", () => {
    expect(checkDiffCap(blast({ files: Array.from({ length: 11 }, (_, i) => `src/f${i}.ts`) })).ok).toBe(false);
    expect(checkDiffCap(blast({ estimatedChangedLines: 400 })).ok).toBe(false);
  });

  it("passes a small mechanical diff", () => {
    expect(checkDiffCap(blast()).ok).toBe(true);
  });
});

describe("checkBlastRadius", () => {
  it("aggregates every violation across the touched file set", () => {
    const r = checkBlastRadius(blast({ files: ["apps/main/src/a.ts", ".env"], createdFiles: ["packages/x.ts"] }), [
      "apps/main/src/**",
    ]);
    expect(r.ok).toBe(false);
    expect(r.violation).toContain("denylisted");
    expect(r.violation).toContain("allowlist");
  });

  it("passes when all files are allowlisted and the diff fits", () => {
    expect(checkBlastRadius(blast(), ["apps/main/src/**"]).ok).toBe(true);
  });
});
