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
import { CORPUS } from "./scan/calibration.js";
import { EXTERNAL_CORPUS } from "./scan/external-corpus.js";
import { SEMANTIC_CORPUS } from "./scan/semantic-corpus.js";

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

  it("reconciles only consumed registry members, including constants, factories and inline spreads", () => {
    const p = repository({
      "src/scan/calibration.ts": "import { entries as used } from './inputs.js'; export const CORPUS = [...used, { id: 'INLINE', kind: 'negative', location: 'inline' }];",
      "src/scan/inputs.ts": [
        "const ROOT = 'fixture';",
        "const DATA = [{ key: 'one' }, { key: 'two' }];",
        "const mapped = DATA.flatMap(c => [{ id: `MAP-${c.key.toUpperCase()}`, kind: 'positive', location: `${ROOT}/${c.key}` }]);",
        "function make(label: string) { const out = []; for (const { key } of DATA) { out.push({ id: `${label}-${key}`, kind: 'negative', location: `${ROOT}/${key}` }); } return out; }",
        "export const entries = [...mapped, ...make('LOOP')];",
        "export const unconsumed = [{ id: 'PHANTOM', kind: 'negative', location: 'not-scored' }];",
      ].join("\n"),
      "src/cli/validate-calibration.ts": "import { CORPUS } from '../scan/calibration.js';",
    });
    const members = (inventory: EnvironmentInventory) => inventory.reconciliations.find((r) => r.registry === "CORPUS imported/spread entries")!.members.map((r) => r.key);
    const before = p.committed();
    expect(members(before)).toEqual(["INLINE", "LOOP-one", "LOOP-two", "MAP-ONE", "MAP-TWO"]);
    const path = join(p.root, "src/scan/inputs.ts"); const original = readFileSync(path, "utf8");
    writeFileSync(path, original.replace("{ key: 'two' }", "{ key: 'two' }, { key: 'three' }"));
    const changed = p.current();
    expect(compareEnvironmentInventory(changed, before).ok).toBe(false);
    expect(members(changed)).toEqual(["INLINE", "LOOP-one", "LOOP-three", "LOOP-two", "MAP-ONE", "MAP-THREE", "MAP-TWO"]);
    writeFileSync(path, original.replace("export const entries = [...mapped, ...make('LOOP')];", "export const entries = process.exit(73);"));
    expect(() => p.current()).toThrow("unresolved registry construction");
    writeFileSync(path, original + "\nentries.push({ id: 'SIDE-EFFECT', kind: 'negative', location: 'late' });");
    expect(() => p.current()).toThrow("top-level effects");
    for (const effect of [
      "const unused = entries.push({ id: 'SIDE', kind: 'negative', location: 'late' });",
      "class Hidden { static { entries.push({ id: 'SIDE', kind: 'negative', location: 'late' }); } }",
      "for (let i = 0; i < 1; i++) entries.push({ id: 'SIDE', kind: 'negative', location: 'late' });",
      "while (false) { entries.push({ id: 'SIDE', kind: 'negative', location: 'late' }); }",
      "const unused = (() => { entries.push({ id: 'SIDE', kind: 'negative', location: 'late' }); return []; })();",
      "const unused = { get measured() { entries.push({ id: 'SIDE', kind: 'negative', location: 'late' }); return 1; } };",
    ]) {
      writeFileSync(path, original + `\n${effect}`);
      expect(() => p.current(), effect).toThrow("unresolved registry construction");
    }
    writeFileSync(path, original + "\nconst unused = make('UNCONSUMED-PURE-FACTORY');");
    expect(members(p.current())).toEqual(members(before));
  });

  it("records declarations and pending decisions without fabricating observation or acceptance", () => {
    const p = repository({
      "workflow": "jobs:\n  evidence:\n    runs-on: macos-15\n    steps:\n      - uses: vendor/action@v1\n      - run: echo proof\n        shell: bash\n        env:\n          TZ: UTC\n",
      "src/recorded-reasons.ts": "export function parseRecordedReasons() {}\nexport function revalidateReasons() {}\n",
      "decision.md": "<!--\nREASON: this is an open operator ruling\nKIND: decisional\nPROVENANCE: MEASURED 2026-09-13 from the recorded question\nOWNER: operator\nDECISION: #1367 (question recorded on the issue with proposed wording)\n-->\n",
    });
    const inventory = p.committed();
    const declaration = inventory.rows.find((r) => r.dependency === "hosted-runner")!;
    expect(declaration).toMatchObject({ observedIdentity: null, identitySource: null, declaredIdentity: "macos-15", pinSource: null, state: "recorded", resolution: "dynamic" });
    expect(inventory.population.authoritativeObservedIdentities).toBe(0);
    expect(inventory.population.authoritativeDeclaredIdentities).toBe(4);
    const decision = inventory.rows.find((r) => r.dependency === "recorded-decision")!;
    expect(decision).toMatchObject({ state: "wholly-unbound", decision: { owner: "operator", disposition: "unverified" } });
    const bad = structuredClone(inventory); bad.rows.find((r) => r.id === decision.id)!.state = "accepted";
    bad.population = censusPopulation(bad.venues, bad.rows);
    expect(() => validateEnvironmentInventory(bad)).toThrow("unverified decision cannot be accepted");
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

  it("rejects a symlink ancestor before reading a tracked descendant", () => {
    const p = repository({ "data/record.ts": "export const value = 71;" });
    const outside = mkdtempSync(join(tmpdir(), "harvey-census-outside-")); dirs.push(outside);
    writeFileSync(join(outside, "record.ts"), "export const externalSentinel = 921;\n");
    rmSync(join(p.root, "data"), { recursive: true });
    symlinkSync(outside, join(p.root, "data"));
    expect(() => p.current()).toThrow("working-tree ancestor is a symlink: data; descendant data/record.ts was not read");
    expect(p.committed().venues.find((v) => v.path === "data/record.ts")?.literalCount).toBe(1);
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
    expect(inventory.reconciliations.find((r) => r.registry === "#1853 external-corpus schema")?.members.map((m) => m.key)).toEqual(EXTERNAL_CORPUS.flatMap((t) => Object.keys(t.modules).map((module) => `${t.slug}:${module}`)).sort());
    expect(inventory.reconciliations.find((r) => r.registry === "CORPUS imported/spread entries")?.members.map((m) => m.key)).toEqual(CORPUS.map((r) => r.id).sort());
    expect(inventory.reconciliations.find((r) => r.registry === "SEMANTIC_CORPUS")?.members.map((m) => m.key)).toEqual(SEMANTIC_CORPUS.map((r) => r.slug).sort());
    for (const target of EXTERNAL_CORPUS) for (const [module, baseline] of Object.entries(target.modules)) {
      const expected = "reason" in baseline ? "revalidateNotRunReasons" : "mutationScore" in baseline ? "scoreMutationBaseline" : "scoreExternalBaseline";
      const row = inventory.rows.find((r) => r.dependency === `${target.slug}@${module}`)!;
      expect(row.consumer.location?.anchor, `${target.slug}:${module}`).toBe(expected);
      expect(row.assertionVenue?.location.anchor, `${target.slug}:${module}`).toBe(`${expected}-call`);
    }
    expect(inventory.rows.find((r) => r.evidence.anchor === "CORPUS/M9P-REMIX-LEAK-POS")).toMatchObject({ assertionVenue: null });
    expect(inventory.rows.find((r) => r.evidence.anchor === "CORPUS/M6-P-JSON-EQUAL")?.assertionVenue?.location.anchor).toBe("scoreM6IndicatorCorpus");
    const truffle = inventory.rows.filter((r) => r.dependency === "trufflehog" && r.evidence.anchor === "captured-output");
    expect(truffle).toHaveLength(2);
    expect(truffle.every((r) => r.pinSource?.identity === "3.97.0" && r.observedIdentity === "3.96.0" && r.state === "recorded" && r.assertionVenue?.scope === "output-schema" && r.schemaOwner?.includes("#1901"))).toBe(true);
    expect(inventory.rows.find((r) => r.venue === "src/__fixtures__/current-mechanical-run-32334325227.json" && r.dependency === "semgrep")).toMatchObject({ observedIdentity: "1.164.0", state: "recorded", pinSource: null });
    expect(inventory.rows.find((r) => r.dependency === "historical-M2-stack")).toMatchObject({ state: "recorded", resolution: "dynamic", freshness: { enforcedBy: null } });
    expect(inventory.rows.some((r) => r.venue === ".github/workflows/issue-1799-hosted-preflight.yml" && r.dependencyClass === "locale" && r.declaredIdentity === "UTC" && r.observedIdentity === null)).toBe(true);
    expect(inventory.rows.filter((r) => r.venue === "docs/tier1-runbook.md" && r.decision?.reference.includes("#1367")).every((r) => r.state === "wholly-unbound" && r.decision?.disposition === "unverified")).toBe(true);
    expect(inventory.rows.some((r) => r.venue === "reports/atc/captures/m8-mutation-broad.json" && r.dependency === "historical-audit-environment")).toBe(true);
  });
});
