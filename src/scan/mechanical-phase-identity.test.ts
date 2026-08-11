import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildMechanicalPhaseCache, discoverMechanicalPhaseImplementationFiles } from "./mechanical-phase-identity.js";

describe("mechanical phase implementation identities (#1864)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  const fixture = (): string => {
    const root = mkdtempSync(join(tmpdir(), "harvey-phase-identity-"));
    dirs.push(root);
    cpSync(join(process.cwd(), "src"), join(root, "src"), { recursive: true });
    cpSync(join(process.cwd(), "tools"), join(root, "tools"), { recursive: true });
    cpSync(join(process.cwd(), "package.json"), join(root, "package.json"));
    cpSync(join(process.cwd(), "pnpm-lock.yaml"), join(root, "pnpm-lock.yaml"));
    return root;
  };
  const buildCache = (root: string) => buildMechanicalPhaseCache({
    repoRoot: root,
    cacheDir: join(root, "cache"),
    mode: "read-write",
    targetRevision: "commit",
    targetTree: "tree",
    optionIdentity: "options",
    registryPackIdentity: { identity: "resolved-registry-packs-v1" },
  });
  const build = (root: string) => buildCache(root).implementation;

  it("a Semgrep rule edit invalidates Semgrep without falsely invalidating unrelated phases", () => {
    const root = fixture();
    const before = build(root);
    writeFileSync(join(root, "src", "scan", "rules", "semgrep", "phase-cache-control.yml"), "rules: []\n");
    const after = build(root);
    expect(after.semgrep).not.toBe(before.semgrep);
    expect(after.configuration).toBe(before.configuration);
    expect(after["structural-ast"]).toBe(before["structural-ast"]);
  });

  it("an auth-guard helper edit invalidates Semgrep without falsely invalidating unrelated phases", () => {
    const root = fixture();
    const before = build(root);
    writeFileSync(join(root, "src", "scan", "auth-guard-discovery.ts"), "\n// phase cache direct dependency control\n", { flag: "a" });
    const after = build(root);
    expect(after.semgrep).not.toBe(before.semgrep);
    expect(after.configuration).toBe(before.configuration);
    expect(after["structural-ast"]).toBe(before["structural-ast"]);
  });

  it("a structural detector edit invalidates only structural/AST", () => {
    const root = fixture();
    const before = build(root);
    writeFileSync(join(root, "src", "scan", "counter-race.ts"), `${Date.now()}\n`, { flag: "a" });
    const after = build(root);
    expect(after["structural-ast"]).not.toBe(before["structural-ast"]);
    expect(after.configuration).toBe(before.configuration);
    expect(after.semgrep).toBe(before.semgrep);
  });

  it("a configuration helper edit invalidates only configuration", () => {
    const root = fixture();
    const before = build(root);
    writeFileSync(join(root, "src", "scan", "supabase-static.ts"), "\n// phase cache configuration dependency control\n", { flag: "a" });
    const after = build(root);
    expect(after.configuration).not.toBe(before.configuration);
    expect(after.semgrep).toBe(before.semgrep);
    expect(after["structural-ast"]).toBe(before["structural-ast"]);
  });

  it("discovers a newly imported phase helper instead of leaving it outside the identity closure", () => {
    const root = fixture();
    const helper = join(root, "src", "scan", "phase-cache-added-helper.ts");
    const mechanical = join(root, "src", "scan", "mechanical.ts");
    writeFileSync(helper, "export function phaseCacheAddedHelper(): void {}\n");
    const source = readFileSync(mechanical, "utf8")
      .replace('import { existsSync, readFileSync } from "node:fs";', 'import { existsSync, readFileSync } from "node:fs";\nimport { phaseCacheAddedHelper } from "./phase-cache-added-helper.js";')
      .replace('const semgrepPhase = await runPhase("semgrep", () => {', 'const semgrepPhase = await runPhase("semgrep", () => {\n      phaseCacheAddedHelper();');
    writeFileSync(mechanical, source);
    expect(discoverMechanicalPhaseImplementationFiles(root).semgrep).toContain(helper);
  });

  it("a pinned dependency-toolchain change invalidates every cacheable phase input identity", () => {
    const root = fixture();
    const before = buildCache(root).externalInputs;
    writeFileSync(join(root, "pnpm-lock.yaml"), "\n# phase cache toolchain control\n", { flag: "a" });
    const after = buildCache(root).externalInputs;
    for (const phase of ["semgrep", "configuration", "structural-ast"] as const) {
      expect(after[phase]?.toolchain).not.toBe(before[phase]?.toolchain);
    }
  });
});
