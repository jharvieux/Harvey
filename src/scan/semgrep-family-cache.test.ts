import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  assertSemgrepFamilyPlan,
  assertSemgrepFamilyVerification,
  discoverLocalSemgrepFamilies,
  executeSemgrepFamily,
  mergeSemgrepFamilyOutputs,
  localSemgrepConfigYardstick,
  rejectUnregisteredSemgrepFamilyArtifacts,
  type SemgrepFamily,
  type SemgrepFamilyCacheOptions,
  type SemgrepFamilyRecord,
} from "./semgrep-family-cache.js";
import type { SemgrepOutput } from "./semgrep.js";

const output = (id: string, path = "src/route.ts"): SemgrepOutput => ({
  results: [{ check_id: id, path, start: { line: 1 }, extra: { message: id, severity: "WARNING" } }],
  errors: [],
  paths: { scanned: [path], skipped: [] },
  time: { rules: [id], fixpoint_timeouts: [] },
});

describe("Semgrep family cache and reassembly (#1869)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  const fixture = (): { root: string; families: SemgrepFamily[]; options: SemgrepFamilyCacheOptions } => {
    const root = mkdtempSync(join(tmpdir(), "harvey-semgrep-family-"));
    dirs.push(root);
    const rules = join(root, "rules");
    mkdirSync(rules);
    const families = ["auth", "xss", "registry"].map((id) => {
      const configPath = join(rules, `${id}.yml`);
      writeFileSync(configPath, `rules: [] # ${id}\n`);
      return { id, configPath };
    });
    return {
      root,
      families,
      options: {
        dir: join(root, "cache"),
        mode: "read-write",
        targetRevision: "commit-a",
        targetTree: "tree-a",
        implementation: "semgrep-wrapper-v1",
        externalInputs: { semgrep: "1.173.0", node: "v24.18.0", toolchain: "lock", options: "pinned" },
      },
    };
  };

  it("requires a stable exhaustive disjoint partition in both directions", () => {
    const { families } = fixture();
    const expected = families.map((family) => family.configPath);
    expect(() => assertSemgrepFamilyPlan(families, expected)).not.toThrow();
    expect(() => assertSemgrepFamilyPlan(families.slice(1), expected)).toThrow("omitted");
    expect(() => assertSemgrepFamilyPlan([...families, families[0]!], expected)).toThrow("duplicate ids");
    expect(() => assertSemgrepFamilyPlan([...families, { id: "unknown", configPath: "/unknown.yml" }], expected)).toThrow("unregistered");
  });

  it("discovers .yml and .yaml through an execution loader independent of the expected-set yardstick", () => {
    const { root } = fixture();
    const rules = join(root, "extension-rules");
    mkdirSync(join(rules, "nested"), { recursive: true });
    writeFileSync(join(rules, "legacy.yml"), "rules: []\n");
    writeFileSync(join(rules, "nested", "new-family.yaml"), "rules: []\n");
    writeFileSync(join(rules, "not-a-rule.txt"), "rules: []\n");
    const discovered = discoverLocalSemgrepFamilies(rules);
    const expected = localSemgrepConfigYardstick(rules);
    expect(discovered.map((family) => family.configPath)).toEqual(expected);
    expect(discovered.map((family) => family.configPath)).toContain(join(rules, "nested", "new-family.yaml"));
    expect(() => assertSemgrepFamilyPlan(discovered.filter((family) => family.configPath.endsWith(".yml")), expected)).toThrow("omitted");
  });

  it("changing one local rule invalidates only its family", async () => {
    const { families, options } = fixture();
    for (const family of families) expect((await executeSemgrepFamily(family, options, () => output(family.id))).cache).toBe("miss");
    writeFileSync(families[0]!.configPath, "rules: [] # auth-v2\n");
    for (const [index, family] of families.entries()) {
      expect((await executeSemgrepFamily(family, options, () => output(`${family.id}-fresh`))).cache).toBe(index === 0 ? "miss" : "hit");
    }
  });

  it("caches a complete zero-applicable-rule family and continues the exhaustive plan", async () => {
    const { families, options } = fixture();
    const empty: SemgrepOutput = { results: [], errors: [], paths: { scanned: [], skipped: [] }, time: { rules: [], fixpoint_timeouts: [] } };
    const cold = await executeSemgrepFamily(families[0]!, options, () => empty);
    const warm = await executeSemgrepFamily(families[0]!, options, () => output("must-not-run"));
    expect(cold).toMatchObject({ cache: "miss", unitsExamined: 1, output: empty });
    expect(warm).toMatchObject({ cache: "hit", unitsExamined: 1, output: empty });
  });

  it("canonicalizes scratch-checkout roots and materializes the current root on a hit", async () => {
    const { root, families, options } = fixture();
    const rootA = join(root, "checkout-a");
    const rootB = join(root, "checkout-b");
    mkdirSync(rootA);
    mkdirSync(rootB);
    const cold = await executeSemgrepFamily(families[0]!, { ...options, pathRoot: rootA }, () => output("auth", join(rootA, "src/route.ts")));
    const warm = await executeSemgrepFamily(families[0]!, { ...options, pathRoot: rootB }, () => output("must-not-run"));
    expect(cold.cache).toBe("miss");
    expect(warm.cache).toBe("hit");
    expect(warm.output.results?.[0]?.path).toBe(join(rootB, "src/route.ts"));
    expect((await executeSemgrepFamily(families[0]!, { ...options, pathRoot: rootB, mode: "verify" }, () => output("auth", join(rootB, "src/route.ts")))).cache).toBe("recomputed");
  });

  it("target and runtime identities invalidate every affected family", async () => {
    const { families, options } = fixture();
    for (const family of families) await executeSemgrepFamily(family, options, () => output(family.id));
    const changed = { ...options, targetTree: "tree-b", externalInputs: { ...options.externalInputs, semgrep: "1.165.0" } };
    for (const family of families) expect((await executeSemgrepFamily(family, changed, () => output(`${family.id}-moved`))).cache).toBe("miss");
  });

  it("rejects corrupt, incomplete, and unregistered artifacts visibly before recompute", async () => {
    const { families, options } = fixture();
    const events: string[] = [];
    options.onEvent = (message) => events.push(message);
    const cold = await executeSemgrepFamily(families[0]!, options, () => output("auth"));
    const artifact = join(options.dir, "semgrep-families", "auth", `${cold.key}.json`);
    const parsed = JSON.parse(readFileSync(artifact, "utf8")) as { output: { paths: unknown }; payloadDigest: string };
    parsed.output.paths = undefined;
    writeFileSync(artifact, JSON.stringify(parsed));
    expect((await executeSemgrepFamily(families[0]!, options, () => output("auth-fresh"))).cache).toBe("miss");
    expect(events).toContainEqual(expect.stringContaining("examined-path scope is incomplete"));

    const unknown = join(options.dir, "semgrep-families", "unknown", "artifact.json");
    mkdirSync(join(options.dir, "semgrep-families", "unknown"), { recursive: true });
    writeFileSync(unknown, JSON.stringify({ schema: 1, family: "not-registered" }));
    rejectUnregisteredSemgrepFamilyArtifacts(options, new Set(families.map((family) => family.id)));
    expect(events).toContainEqual(expect.stringContaining("artifact is unregistered"));
  });

  it("reassembles deterministic monolithic shape with exact deduplication", () => {
    const duplicate = output("tmp.cache-a.registry-packs.digest.javascript.react.same").results![0]!;
    const sameRegistryRule = { ...duplicate, check_id: "tmp.cache-b.registry-packs.digest.javascript.react.same" };
    const merged = mergeSemgrepFamilyOutputs([
      { family: "b", output: { ...output("b"), results: [duplicate, output("b").results![0]!], time: { rules: ["same", "b"], fixpoint_timeouts: [] } }, cache: "hit", key: "b", unitsExamined: 1 },
      { family: "a", output: { ...output("a"), results: [sameRegistryRule, output("a").results![0]!], time: { rules: ["same", "a"], fixpoint_timeouts: [] } }, cache: "hit", key: "a", unitsExamined: 1 },
    ]);
    expect(merged.results?.map((result) => result.check_id)).toEqual(["a", "b", "javascript.react.same"]);
    expect(merged.paths?.scanned).toEqual(["src/route.ts"]);
    expect(merged.time?.rules).toEqual(["a", "b", "same"]);
  });

  it("conserves, deduplicates, and root-materializes fixpoint timeout evidence", async () => {
    const { root, families, options } = fixture();
    const rootA = join(root, "checkout-a");
    const rootB = join(root, "checkout-b");
    mkdirSync(rootA);
    mkdirSync(rootB);
    const timeout = (pathRoot: string) => ({
      error_type: "Fixpoint timeout", severity: "warn",
      message: `Fixpoint timeout at ${join(pathRoot, "src/route.ts")}:1:0`,
      location: { path: join(pathRoot, "src/route.ts"), start: { line: 1 }, end: { line: 1 } },
    });
    const cold = await executeSemgrepFamily(families[0]!, { ...options, pathRoot: rootA }, () => ({
      ...output("auth", join(rootA, "src/route.ts")),
      time: { rules: ["auth"], fixpoint_timeouts: [timeout(rootA)] },
    }));
    const warm = await executeSemgrepFamily(families[0]!, { ...options, pathRoot: rootB }, () => output("must-not-run"));
    expect(cold.output.time?.fixpoint_timeouts).toHaveLength(1);
    expect(warm.output.time?.fixpoint_timeouts).toEqual([timeout(rootB)]);

    const merged = mergeSemgrepFamilyOutputs([
      { ...cold, output: { ...cold.output, time: { rules: ["auth"], fixpoint_timeouts: [timeout(rootA)] } } },
      { family: "duplicate", output: { ...cold.output, time: { rules: ["other"], fixpoint_timeouts: [timeout(rootA)] } }, cache: "miss", key: "duplicate", unitsExamined: 1 },
    ]);
    expect(merged.time?.fixpoint_timeouts).toEqual([timeout(rootA)]);
  });

  it("rejects legacy or unknown time evidence before cache storage", async () => {
    const { families, options } = fixture();
    await expect(executeSemgrepFamily(families[0]!, options, () => ({
      ...output("auth"), time: { rules: ["auth"] },
    }))).rejects.toThrow(/fixpoint_timeouts population is missing/);
    await expect(executeSemgrepFamily(families[0]!, options, () => ({
      ...output("auth"), time: { rules: ["auth"], fixpoint_timeouts: [], future: [] },
    }))).rejects.toThrow(/unclassified child evidence.*future/);
  });

  it("conserves distinct same-path errors and removes only exact cross-family duplicates", () => {
    const first = { path: "/target/src/broken.ts", type: ["PartialParsing", [{ line: 42 }]], message: "first partial parse" };
    const second = { path: "/target/src/broken.ts", type: ["PartialParsing", [{ line: 47 }]], message: "second partial parse" };
    const merged = mergeSemgrepFamilyOutputs([
      { family: "a", output: { ...output("a"), errors: [first, second] }, cache: "miss", key: "a", unitsExamined: 1 },
      { family: "b", output: { ...output("b"), errors: [first] }, cache: "miss", key: "b", unitsExamined: 1 },
    ]);
    expect(merged.errors).toEqual([first, second]);
  });

  it("does not erase an exact duplicate emitted twice by one family", () => {
    const repeated = { path: "/target/src/broken.ts", type: "ParseError", message: "same engine record twice" };
    const merged = mergeSemgrepFamilyOutputs([
      { family: "a", output: { ...output("a"), errors: [repeated, repeated] }, cache: "miss", key: "a", unitsExamined: 1 },
      { family: "b", output: { ...output("b"), errors: [repeated] }, cache: "miss", key: "b", unitsExamined: 1 },
    ]);
    expect(merged.errors).toEqual([repeated, repeated]);
  });

  it("stores and rereads every same-path diagnostic without collapsing its structure", async () => {
    const { families, options } = fixture();
    const first = { path: "/target/src/broken.ts", type: ["PartialParsing", [{ line: 42 }]], message: "first partial parse" };
    const second = { path: "/target/src/broken.ts", type: ["PartialParsing", [{ line: 47 }]], message: "second partial parse" };
    const complete: SemgrepOutput = { ...output("auth"), errors: [first, second] };
    const cold = await executeSemgrepFamily(families[0]!, options, () => complete);
    const warm = await executeSemgrepFamily(families[0]!, options, () => output("must-not-run"));
    expect(cold.output.errors).toEqual([first, second]);
    expect(warm.output.errors).toEqual([first, second]);
  });

  it("preserves the monolithic namespace for a local Harvey rule loaded as one family", () => {
    const merged = mergeSemgrepFamilyOutputs([
      { family: "local", output: output("harvey-route-noauth"), cache: "miss", key: "local", unitsExamined: 1 },
    ]);
    expect(merged.results?.map((result) => result.check_id)).toEqual(["src.scan.rules.semgrep.harvey-route-noauth"]);
  });

  it("forced-cold verification passes only when every family re-executed against a hit", async () => {
    const { families, options } = fixture();
    for (const family of families) await executeSemgrepFamily(family, options, () => output(family.id));
    const verified: SemgrepFamilyRecord[] = [];
    for (const family of families) verified.push(await executeSemgrepFamily(family, { ...options, mode: "verify" }, () => output(family.id)));
    expect(() => assertSemgrepFamilyVerification(verified, families, "verify")).not.toThrow();
    expect(verified.every((record) => record.cache === "recomputed")).toBe(true);

    const empty = fixture();
    const misses: SemgrepFamilyRecord[] = [];
    for (const family of empty.families) misses.push(await executeSemgrepFamily(family, { ...empty.options, mode: "verify" }, () => output(family.id)));
    expect(() => assertSemgrepFamilyVerification(misses, empty.families, "verify")).toThrow("forced-cold Semgrep family verification incomplete");
  });
});
