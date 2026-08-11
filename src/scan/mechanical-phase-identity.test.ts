import { cpSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildMechanicalPhaseCache } from "./mechanical-phase-identity.js";

describe("mechanical phase implementation identities (#1864)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  const fixture = (): string => {
    const root = mkdtempSync(join(tmpdir(), "harvey-phase-identity-"));
    dirs.push(root);
    cpSync(join(process.cwd(), "src", "scan"), join(root, "src", "scan"), { recursive: true });
    return root;
  };
  const build = (root: string) => buildMechanicalPhaseCache({
    repoRoot: root,
    cacheDir: join(root, "cache"),
    mode: "read-write",
    targetRevision: "commit",
    targetTree: "tree",
    optionIdentity: "options",
    registryPackIdentity: { identity: "resolved-registry-packs-v1" },
  }).implementation;

  it("a Semgrep rule edit invalidates Semgrep without falsely invalidating unrelated phases", () => {
    const root = fixture();
    const before = build(root);
    writeFileSync(join(root, "src", "scan", "rules", "semgrep", "phase-cache-control.yml"), "rules: []\n");
    const after = build(root);
    expect(after.semgrep).not.toBe(before.semgrep);
    expect(after["secrets-history"]).toBe(before["secrets-history"]);
    expect(after.configuration).toBe(before.configuration);
    expect(after["structural-ast"]).toBe(before["structural-ast"]);
  });

  it("a structural detector edit invalidates structural/configuration but not Semgrep or secrets", () => {
    const root = fixture();
    const before = build(root);
    writeFileSync(join(root, "src", "scan", "counter-race.ts"), `${Date.now()}\n`, { flag: "a" });
    const after = build(root);
    expect(after["structural-ast"]).not.toBe(before["structural-ast"]);
    expect(after.configuration).not.toBe(before.configuration);
    expect(after.semgrep).toBe(before.semgrep);
    expect(after["secrets-history"]).toBe(before["secrets-history"]);
  });
});
