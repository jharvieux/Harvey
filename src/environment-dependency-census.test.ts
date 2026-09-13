import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { buildEnvironmentInventory, compareEnvironmentInventory } from "./environment-dependency-census.js";
import { readCensusSnapshot } from "./environment-dependency-census-discovery.js";
import { censusJson, censusPopulation, ENVIRONMENT_CLASSES, validateEnvironmentInventory, type EnvironmentInventory } from "./environment-dependency-census-schema.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function repository(files: Record<string, string | Buffer> = { "unusual/place.ts": "export const x = [71, 'opaque label'];\n" }) {
  const root = mkdtempSync(join(tmpdir(), "harvey-environment-census-")); dirs.push(root);
  const git = (args: string[]) => execFileSync("git", args, { cwd: root, encoding: "utf8" });
  git(["init", "--quiet"]);
  for (const [path, text] of Object.entries(files)) { mkdirSync(dirname(join(root, path)), { recursive: true }); writeFileSync(join(root, path), text); }
  git(["add", "."]);
  git(["-c", "user.name=Census test", "-c", "user.email=census@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Seed physical census control"]);
  const committed = () => buildEnvironmentInventory(readCensusSnapshot(root, "HEAD"));
  const current = () => buildEnvironmentInventory(readCensusSnapshot(root, undefined, true));
  return { root, git, committed, current };
}

describe("environment census discovery and typed completeness (#1906)", () => {
  it("discovers all blob formats and ordinary inline literals without filename evidence hints", () => {
    const p = repository({
      "unusual/place.ts": "export const opaque = [71, 'plain measurement'];\n",
      "anywhere/notes": "measurement 8.25 ms under node 24.19.0\n",
      "anywhere/no-extension": JSON.stringify({ measuredAt: "2026-09-13", environmentDependencyClass: "hardware", cpuModel: "physical control" }),
      "anywhere/capture.dat": gzipSync(JSON.stringify({ generatedAt: "2026-09-13", nodeVersion: "24.19.0" })),
      "anywhere/opaque.bin": Buffer.from([0xff, 0, 0x89]),
    });
    const inventory = p.committed();
    expect(inventory.venues.map((v) => v.path)).toHaveLength(5);
    expect(inventory.venues.find((v) => v.path.endsWith("place.ts"))?.literalCount).toBe(2);
    expect(inventory.venues.find((v) => v.path.endsWith("capture.dat"))?.format).toBe("gzip/json");
    expect(inventory.venues.find((v) => v.path.endsWith("opaque.bin"))?.disposition).toBe("opaque-unresolved");
    for (const venue of inventory.venues) expect(inventory.rows.some((r) => r.venue === venue.id && r.dependency === "unclassified-content" && r.state === "wholly-unbound")).toBe(true);
    expect(inventory.population.classes.find((r) => r.dependencyClass === "hardware")?.rows).toBe(1);
    expect(inventory.population.classes.find((r) => r.dependencyClass === "database")?.emptyReason).toContain("not proof");
    expect(compareEnvironmentInventory(p.current(), inventory)).toEqual({ ok: true, problems: [] });
  });

  it("physical add and remove controls change the production completeness verdict", () => {
    const p = repository(); const before = p.committed();
    writeFileSync(join(p.root, "new-venue"), "measured result 73 with shell bash\n");
    expect(compareEnvironmentInventory(p.current(), before).problems).toContain("unregistered-venue: new-venue needs an owned row or explicit unresolved reason in a regenerated immutable census");
    rmSync(join(p.root, "new-venue")); rmSync(join(p.root, "unusual/place.ts"));
    writeFileSync(join(p.root, "other"), "keeps the examined population nonempty\n");
    expect(compareEnvironmentInventory(p.current(), before).problems).toContain("removed-venue: unusual/place.ts; the retained population no longer exists");
  });

  it("hidden inline addition is red and immutable ref reads ignore dirty bytes", () => {
    const p = repository(); const before = p.committed();
    writeFileSync(join(p.root, "unusual/place.ts"), "export const x = [71, 'opaque label'];\nexport const q = 0.8123;\n");
    expect(compareEnvironmentInventory(p.current(), before).problems.some((v) => v.startsWith("changed-venue: unusual/place.ts"))).toBe(true);
    expect(censusJson(p.committed())).toBe(censusJson(before));
    const regenerated = p.current();
    expect(regenerated.rows.find((r) => r.venue === "unusual/place.ts" && r.dependency === "unclassified-content")).toMatchObject({ state: "wholly-unbound", resolution: "unresolved", observedIdentity: null, pinSource: null, assertionVenue: null });
  });

  it("census implementation/test files are covered while only circular outputs are excluded", () => {
    const p = repository({ "src/environment-dependency-census.ts": "export const measured = 1;\n", "src/environment-dependency-census.test.ts": "const raw = 'captured';\n", "src/environment-dependency-inventory.json": "{}\n", "docs/design/environment-dependency-census.md": "generated population\n" });
    const before = p.committed();
    expect(before.venues.map((v) => v.path)).toEqual(["src/environment-dependency-census.test.ts", "src/environment-dependency-census.ts"]);
    writeFileSync(join(p.root, "src/environment-dependency-census.ts"), "export const measured = 2;\n");
    expect(compareEnvironmentInventory(p.current(), before).ok).toBe(false);
    expect(before.exclusions.map((e) => e.path)).toEqual(["src/environment-dependency-inventory.json", "docs/design/environment-dependency-census.md"]);
  });

  it("retains unresolved residue inside an adapted workflow after hidden literal regeneration", () => {
    const text = "jobs:\n  evidence:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo proof\n        shell: bash\n";
    const p = repository({ "unusual/work": text }); const before = p.committed();
    writeFileSync(join(p.root, "unusual/work"), `${text}        env:\n          UNLABELLED_RECORDED_VALUE: 0.8123\n`);
    const after = p.current();
    expect(after.venues[0]?.disposition).toBe("authoritative-adapter");
    expect(compareEnvironmentInventory(after, before).ok).toBe(false);
    expect(after.rows.find((r) => r.dependency === "unclassified-content")).toMatchObject({ state: "wholly-unbound", resolution: "unresolved" });
  });

  it("unknown explicit dependency class and missing owned rows cannot be normalized away", () => {
    const p = repository(); const before = p.committed();
    writeFileSync(join(p.root, "venue"), '{"environmentDependencyClass":"new-unregistered-class"}\n');
    expect(() => p.current()).toThrow("unregistered environment dependency class new-unregistered-class");
    const unknown = structuredClone(before) as EnvironmentInventory;
    (unknown.analyzer.classes as string[]).push("new-class");
    expect(() => validateEnvironmentInventory(unknown)).toThrow("unregistered dependency class");
    const missing = structuredClone(before); missing.rows = [];
    expect(() => compareEnvironmentInventory(before, missing)).toThrow("empty examined population");
  });

  it("authenticates immutable provenance without trusting a rewritten SHA or requiring local history", () => {
    const p = repository(); const before = p.committed();
    const badCommit = structuredClone(before); badCommit.source.commit = "a".repeat(40);
    expect(() => validateEnvironmentInventory(badCommit)).toThrow("immutable commit proof");
    const badBlob = structuredClone(before); badBlob.venues[0]!.gitOid = "b".repeat(40);
    expect(() => validateEnvironmentInventory(badBlob)).toThrow("immutable tree proof");
    const transient = p.current();
    expect(() => compareEnvironmentInventory(transient, transient)).toThrow("must come from an immutable committed revision");
    rmSync(join(p.root, ".git"), { recursive: true, force: true });
    expect(() => validateEnvironmentInventory(before)).not.toThrow();
  });

  it("removing identity, pin, owner, consumer or assertion cannot leave a pinned classification", () => {
    const p = repository(); const inventory = p.committed();
    const r = structuredClone(inventory.rows[0]!);
    r.id += "-pinned-control";
    r.classification = "authoritative-record";
    inventory.rows.push(r);
    const location = { path: "unusual/place.ts", anchor: "physical", line: 1 };
    Object.assign(r, { state: "pinned", resolution: "identified", observedIdentity: "1.2.3", identitySource: location, pinSource: { location, identity: "1.2.3", scope: "output-schema" }, assertionVenue: { location, scope: "output-schema", claim: "Only shape checked" }, consumer: { location, resolution: "authoritative", reason: "Control parser" } });
    inventory.population = censusPopulation(inventory.venues, inventory.rows);
    expect(() => validateEnvironmentInventory(inventory)).not.toThrow();
    expect(inventory.population.environmentAssertions).toBe(0);
    for (const key of ["observedIdentity", "pinSource", "identitySource", "assertionVenue", "owner"] as const) {
      const bad = structuredClone(inventory); (bad.rows.at(-1) as unknown as Fields)[key] = null;
      expect(() => validateEnvironmentInventory(bad), key).toThrow();
    }
    const conflict = structuredClone(inventory); conflict.rows.at(-1)!.pinSource!.identity = "9.9.9";
    expect(() => validateEnvironmentInventory(conflict)).toThrow("unproven identity pin");
  });

  it("does not follow symlinks and still notices changed symlink bytes", () => {
    const p = repository(); symlinkSync("/outside/measurement", join(p.root, "external-link")); p.git(["add", "."]);
    p.git(["-c", "user.name=Census test", "-c", "user.email=census@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Retain symlink control"]);
    const before = p.committed();
    expect(compareEnvironmentInventory(p.current(), before).ok).toBe(true);
    expect(before.venues.find((v) => v.path === "external-link")?.format).toBe("symlink");
    rmSync(join(p.root, "external-link")); symlinkSync("/different/measurement", join(p.root, "external-link"));
    expect(compareEnvironmentInventory(p.current(), before).ok).toBe(false);
  });
});

type Fields = Record<string, unknown>;

function checkCurrentInventory(): Promise<{ status: number; output: string }> {
  return new Promise((done, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", join(ROOT, "src/cli/environment-dependency-census.ts"), "--check"], { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
    child.stdout.on("data", (text: string) => { output += text; });
    child.stderr.on("data", (text: string) => { output += text; });
    child.once("error", reject);
    child.once("close", (status) => done({ status: status ?? 1, output }));
  });
}

describe("committed environment population and existing owner seams (#1906)", () => {
  it("matches every current input and preserves actual narrower populations and historical identities", async () => {
    const result = await checkCurrentInventory();
    expect(result.status, result.output).toBe(0);
    const inventory = JSON.parse(readFileSync(join(ROOT, "src/environment-dependency-inventory.json"), "utf8")) as EnvironmentInventory;
    expect(inventory.population.classes.map((c) => c.dependencyClass)).toEqual([...ENVIRONMENT_CLASSES]);
    expect(inventory.reconciliations.find((r) => r.registry === "#1853 external-corpus schema")?.members.length).toBeGreaterThan(100);
    expect(inventory.reconciliations.find((r) => r.registry === "CORPUS imported/spread entries")?.members.length).toBeGreaterThan(100);
    expect(inventory.reconciliations.find((r) => r.registry === "SEMANTIC_CORPUS")?.members.length).toBeGreaterThan(0);
    const truffle = inventory.rows.filter((r) => r.dependency === "trufflehog" && r.evidence.anchor === "captured-output");
    expect(truffle).toHaveLength(2);
    expect(truffle.every((r) => r.pinSource?.identity === "3.97.0" && r.observedIdentity === "3.96.0" && r.state === "recorded" && r.assertionVenue?.scope === "output-schema" && r.schemaOwner?.includes("#1901"))).toBe(true);
    expect(inventory.rows.find((r) => r.venue === "src/__fixtures__/current-mechanical-run-32334325227.json" && r.dependency === "semgrep")).toMatchObject({ observedIdentity: "1.164.0", state: "recorded", pinSource: null });
    expect(inventory.rows.find((r) => r.dependency === "historical-M2-stack")).toMatchObject({ state: "recorded", resolution: "dynamic", freshness: { enforcedBy: null } });
    expect(inventory.rows.some((r) => r.venue === ".github/workflows/issue-1799-hosted-preflight.yml" && r.dependencyClass === "locale" && r.observedIdentity === "UTC")).toBe(true);
    expect(inventory.rows.some((r) => r.venue === "reports/atc/captures/m8-mutation-broad.json" && r.dependency === "historical-audit-environment")).toBe(true);
  });
});
