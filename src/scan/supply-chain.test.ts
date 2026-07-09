import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { checkInstallScripts, checkLockfilePresence, checkTyposquat, checkUnpinnedDependencies } from "./supply-chain.js";

describe("checkTyposquat", () => {
  it("flags a name one edit from a popular package", () => {
    const findings = checkTyposquat(["expres", "react"]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toContain("expres");
    expect(findings[0]?.precisionTier).toBe("review");
  });

  it("does not flag an exact popular-package match", () => {
    expect(checkTyposquat(["express", "react"])).toEqual([]);
  });

  it("does not flag unrelated names with no close popular match", () => {
    expect(checkTyposquat(["my-internal-utils"])).toEqual([]);
  });
});

describe("checkUnpinnedDependencies", () => {
  it("flags caret/tilde/wildcard ranges as high precision", () => {
    const findings = checkUnpinnedDependencies({ react: "^18.2.0", zod: "3.22.0", lodash: "*" });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("react@^18.2.0");
    expect(findings[0]?.evidence).toContain("lodash@*");
    expect(findings[0]?.evidence).not.toContain("zod@");
    expect(findings[0]?.precisionTier).toBe("high");
  });

  it("returns no finding when every dependency is exactly pinned", () => {
    expect(checkUnpinnedDependencies({ react: "18.2.0", zod: "3.22.0" })).toEqual([]);
  });
});

describe("checkInstallScripts", () => {
  it("flags a postinstall lifecycle script at review tier", () => {
    const findings = checkInstallScripts({ build: "next build", postinstall: "node ./setup.js" });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("postinstall");
    expect(findings[0]?.precisionTier).toBe("review");
  });

  it("does not flag when no install lifecycle hooks are present", () => {
    expect(checkInstallScripts({ build: "next build", test: "vitest" })).toEqual([]);
  });
});

describe("checkLockfilePresence", () => {
  let dir: string;
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("flags a project directory with no lockfile", () => {
    dir = mkdtempSync(join(tmpdir(), "harvey-lockfile-"));
    expect(checkLockfilePresence(dir)).toHaveLength(1);
  });

  it("does not flag a directory with pnpm-lock.yaml present", () => {
    dir = mkdtempSync(join(tmpdir(), "harvey-lockfile-"));
    writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    expect(checkLockfilePresence(dir)).toEqual([]);
  });
});
