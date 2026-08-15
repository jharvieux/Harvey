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
    writeFileSync(join(root, "registry.yml"), "rules: []\n");
    return root;
  };
  const buildCache = (root: string) => buildMechanicalPhaseCache({
    repoRoot: root,
    cacheDir: join(root, "cache"),
    mode: "read-write",
    targetRevision: "commit",
    targetTree: "tree",
    optionIdentity: "options",
    registryPackIdentity: { identity: "resolved-registry-packs-v1", files: [join(root, "registry.yml")] },
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

  it("a pinned Semgrep worker-topology edit or removal invalidates phase and family caches", () => {
    const root = fixture();
    const before = buildCache(root);
    const semgrep = join(root, "src", "scan", "semgrep.ts");
    const original = readFileSync(semgrep, "utf8");
    for (const replacement of [
      '["--x-ignore-semgrepignore-files", "--x-parmap", "-j", "8"]',
      '["--x-ignore-semgrepignore-files", "--x-parmap"]',
    ]) {
      const source = original.replace(
        '["--x-ignore-semgrepignore-files", "--x-parmap", "-j", "9"]',
        replacement,
      );
      expect(source).toContain(replacement);
      writeFileSync(semgrep, source);
      const after = buildCache(root);
      expect(after.implementation.semgrep).not.toBe(before.implementation.semgrep);
      expect(after.semgrepFamilies?.implementation).not.toBe(before.semgrepFamilies?.implementation);
    }
  });

  it("an auth-guard helper edit invalidates every consuming phase but not configuration", () => {
    const root = fixture();
    const before = build(root);
    writeFileSync(join(root, "src", "scan", "auth-guard-discovery.ts"), "\n// phase cache direct dependency control\n", { flag: "a" });
    const after = build(root);
    expect(after.semgrep).not.toBe(before.semgrep);
    expect(after.configuration).toBe(before.configuration);
    expect(after["structural-ast"]).not.toBe(before["structural-ast"]);
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

  it("follows shared-context ownership into deterministic dependency advisory identity", () => {
    const root = fixture();
    const files = discoverMechanicalPhaseImplementationFiles(root, ["dependency-advisory"])["dependency-advisory"]!;
    expect(files).toContain(join(root, "src", "scan", "mechanical-context.ts"));
    expect(files).toContain(join(root, "src", "workspaces.ts"));
    expect(buildMechanicalPhaseCache({
      repoRoot: root,
      cacheDir: join(root, "cache"),
      mode: "read-write",
      targetRevision: "commit",
      targetTree: "tree",
      optionIdentity: "options",
      registryPackIdentity: { identity: "resolved-registry-packs-v1" },
      deterministicExternalState: {
        advisoryDigest: "advisory-snapshot",
        advisoryVersion: "osv-scanner-test",
        secretCandidateIdentity: "secret-candidates",
      },
    }).implementation["dependency-advisory"]).toBeTruthy();
  });

  it("keeps empty implementation ownership a loud failure", () => {
    const root = fixture();
    const mechanical = join(root, "src", "scan", "mechanical.ts");
    writeFileSync(mechanical, `async function scan(): Promise<void> {
  const runPhase = async (_phase: string, execute: () => unknown): Promise<unknown> => execute();
  await runPhase("dependency-advisory", () => ({
    findings: [],
    scope: { unitsExamined: 1, description: "no implementation ownership" },
  }));
}
void scan;
`);
    expect(() => discoverMechanicalPhaseImplementationFiles(root, ["dependency-advisory"]))
      .toThrow("dependency-advisory: no implementation helpers discovered from its runPhase callback");
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
      .replace('import type { Finding } from "../findings.js";', 'import type { Finding } from "../findings.js";\nimport { phaseCacheAddedHelper } from "./phase-cache-added-helper.js";')
      .replace(
        'const result = await runRegisteredSemgrepEngines({ scanDir, context, phaseCache: opts.phaseCache, authGuards: opts.authGuards, unitsExamined: allUnits });',
        'const result = (phaseCacheAddedHelper(), await runRegisteredSemgrepEngines({ scanDir, context, phaseCache: opts.phaseCache, authGuards: opts.authGuards, unitsExamined: allUnits }));',
      );
    expect(source).toContain('import { phaseCacheAddedHelper } from "./phase-cache-added-helper.js";');
    expect(source).toContain("phaseCacheAddedHelper(),");
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

  it("a Node runtime change invalidates exactly every phase that executes Node-driven logic", () => {
    const root = fixture();
    const before = buildCache(root).externalInputs;
    const nodeDependent = (["semgrep", "configuration", "structural-ast"] as const).filter((phase) => before[phase]?.node === process.version);
    expect(nodeDependent).toEqual(["semgrep", "configuration", "structural-ast"]);
    const after = Object.fromEntries(Object.entries(before).map(([phase, inputs]) => [phase, inputs?.node
      ? { ...inputs, node: "v-next-runtime" }
      : inputs])) as typeof before;
    const movedPhases = (["semgrep", "configuration", "structural-ast"] as const).filter((phase) =>
      JSON.stringify(before[phase]) !== JSON.stringify(after[phase]));
    expect(movedPhases).toEqual(["semgrep", "configuration", "structural-ast"]);
    for (const phase of movedPhases) {
      const movedInputs = Object.keys(after[phase]!).filter((name) => before[phase]?.[name] !== after[phase]?.[name]);
      expect(movedInputs).toEqual(["node"]);
    }
  });

  it("makes Semgrep explicitly non-cacheable when a retry restored no exact attempt-1 snapshot", () => {
    const root = fixture();
    const events: string[] = [];
    const cache = buildMechanicalPhaseCache({
      repoRoot: root,
      cacheDir: join(root, "cache"),
      mode: "read-write",
      targetRevision: "commit",
      targetTree: "tree",
      optionIdentity: "options",
      registrySnapshotMode: "unavailable",
      onEvent: (message) => events.push(message),
    });
    expect(cache.disabled?.semgrep).toContain("did not restore the exact attempt-1 phase cache");
    expect(events).toContainEqual(expect.stringContaining("SEMGREP REGISTRY SNAPSHOT UNAVAILABLE"));
  });
});
