import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const CLI = join(ROOT, "src/cli/environment-dependency-census.ts");
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function prepare() {
  const dir = mkdtempSync(join(tmpdir(), "harvey-env-census-cli-")); dirs.push(dir);
  const root = join(dir, "repo"); mkdirSync(root);
  const git = (args: string[]) => execFileSync("git", args, { cwd: root, encoding: "utf8" });
  git(["init", "--quiet"]);
  mkdirSync(join(root, "unrelated"));
  writeFileSync(join(root, "unrelated/ordinary.ts"), "export const x = 71;\n");
  writeFileSync(join(root, "original-output"), '{"recordedAt":"2026-09-13","result":71}\n');
  git(["add", "."]);
  git(["-c", "user.name=Census control", "-c", "user.email=census@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Seed CLI controls"]);
  return { root, dir, git, inventory: join(dir, "inventory.json"), head: git(["rev-parse", "HEAD"]).trim() };
}

function runNode(args: string[]): Promise<{ status: number; output: string }> {
  return new Promise((done, reject) => {
    const child = spawn(process.execPath, args, { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
    child.stdout.on("data", (text: string) => { output += text; });
    child.stderr.on("data", (text: string) => { output += text; });
    child.once("error", reject);
    child.once("close", (status) => done({ status: status ?? 1, output }));
  });
}

const run = (args: string[]) => runNode(["--import", "tsx", CLI, ...args]);

function registryControl(source: string, siblings: Record<string, string | Uint8Array> = {}) {
  const p = prepare();
  mkdirSync(join(p.root, "src/scan"), { recursive: true });
  writeFileSync(join(p.root, "package.json"), '{"type":"module"}\n');
  writeFileSync(join(p.root, "src/scan/calibration.ts"), source);
  for (const [path, text] of Object.entries(siblings)) writeFileSync(join(p.root, "src/scan", path), text);
  p.git(["add", "."]);
  p.git(["-c", "user.name=Census control", "-c", "user.email=census@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Add registry evaluation control"]);
  return p;
}

describe("environment dependency shipping CLI (#1906)", () => {
  it.each([
    ["some short circuit", "const out = [BASE]; [ONE, TWO].some(entry => { out.push(entry); return true; }); return out;"],
    ["some exhaustion", "const out = [BASE]; [ONE, TWO].some(entry => { out.push(entry); return false; }); return out;"],
    ["flatMap immediate flattening", "const shared = []; return [BASE, ONE].flatMap(entry => { const prior = shared.length; shared.push(entry); return prior ? [] : shared; });"],
    ["map length snapshot", "const input = [BASE]; return input.map(entry => { input.push(ONE); return entry; });"],
    ["filter length snapshot", "const input = [BASE]; return input.filter(() => { input.push(ONE); return true; });"],
    ["replace substitution", "return [{ ...BASE, id: BASE.id.replace(/^BASE/, '$&-EXACT') }];"],
    ["replace dollar and suffix", "return [{ ...BASE, id: 'BASE-tail'.replace(/^BASE/, \"$$$&$'\") }];"],
    ["Set size branch", "return seen.size ? [ONE] : [BASE];"],
  ])("matches native module membership for %s", async (_, body) => {
    const p = registryControl(`const BASE = { id: 'BASE', kind: 'positive', location: 'fixture' };
const ONE = { ...BASE, id: 'ONE' }; const TWO = { ...BASE, id: 'TWO' }; const seen = new Set(['one']);
function make() { ${body} }
export const CORPUS = make();\n`);
    // Only this test's newly authored fixture is executed; census input remains unevaluated by the CLI.
    const oracle = await runNode(["--input-type=module", "--eval", `const { CORPUS } = await import(${JSON.stringify(pathToFileURL(join(p.root, "src/scan/calibration.ts")).href)}); console.log(JSON.stringify(CORPUS.map(entry => entry.id).sort()));`]);
    expect(oracle.status, oracle.output).toBe(0);
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(0);
    const inventory = JSON.parse(readFileSync(p.inventory, "utf8")) as { reconciliations: { registry: string; members: { key: string }[] }[] };
    expect(inventory.reconciliations.find(row => row.registry === "CORPUS imported/spread entries")?.members.map(member => member.key)).toEqual(JSON.parse(oracle.output));
  });

  it.each([
    ["every remains unsupported", "const ignored = [BASE].every(entry => { return false; });", "method every is not modeled"],
    ["empty array invalid callback", "const ignored = [].map(undefined);", "array callback must be a source-local function"],
    ["truthy Set size guard", "const seen = new Set(['one']); if (seen.size) { throw new Error('invalid population'); }", "registry admission guard rejected"],
    ["unmodeled inherited property", "const seen = new Set(['one']); const ignored = seen.has;", "property has is not modeled"],
  ])("refuses to publish when %s", async (_, prefix, error) => {
    const p = registryControl(`const BASE = { id: 'BASE', kind: 'positive', location: 'fixture' };\n${prefix}\nexport const CORPUS = [BASE];\n`);
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain(error);
  });

  it("admits unused value-import modules before publishing registry membership", async () => {
    const p = registryControl("import { BASE } from './data.ts'; import { effect } from './effect.ts'; export function unused() { return effect; } export const CORPUS = BASE;\n", {
      "data.ts": "export const BASE = [{ id: 'BASE', kind: 'positive', location: 'fixture' }];\n",
      "effect.ts": "import { BASE } from './data.ts'; BASE.push({ id: 'SIDE', kind: 'positive', location: 'fixture' }); export const effect = true;\n",
    });
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain("top-level effects are outside the registry grammar");
  });

  it.each([
    ["unused initializer mutation", "import { BASE } from './data.ts'; const ignored = BASE.push({ id: 'SIDE', kind: 'positive', location: 'fixture' }); export const effect = true;", "unused initializer may mutate registry data"],
    ["shadowed undefined initializer", "import { BASE } from './data.ts'; const undefined = BASE.push({ id: 'SIDE', kind: 'positive', location: 'fixture' }); export const effect = true;", "unused initializer may mutate registry data"],
    ["transitive namespace import", "import * as nested from './nested.ts'; export function effect() { return nested; }", "top-level effects are outside the registry grammar"],
    ["transitive side-effect import", "import './nested.ts'; export const effect = true;", "top-level effects are outside the registry grammar"],
    ["unknown imported semantic value", "import { metadata } from 'unresolved-package'; const ignored = metadata ? 1 : 0; export const effect = true;", "unknown semantic value"],
    ["opaque path admission condition", "import { resolve } from 'node:path'; import { fileURLToPath } from 'node:url'; const root = resolve(fileURLToPath(import.meta.url), '..'); if (root) { throw new Error('unknown'); } export const effect = true;", "unknown semantic value"],
    ["unknown initialization call", "import { mystery } from 'unresolved-package'; const ignored = mystery(); export const effect = true;", "is not demonstrably inert"],
    ["opaque Set membership", "import { metadata } from 'unresolved-package'; const seen = new Set([metadata]); if (seen.size) { throw new Error('unknown'); } export const effect = true;", "unknown semantic Set membership"],
    ["class parameter decorator", "function decorate() { return true; } class Metadata { constructor(@decorate value) {} } export const effect = true;", "top-level effects are outside the registry grammar"],
    ["missing named value export", "const effect = true;", "unresolved value import effect"],
    ["derived opaque URL base", "import { fileURLToPath } from 'node:url'; const base = fileURLToPath(import.meta.url); const ignored = new URL('./input.json', base); export const effect = true;", "inert constructor arguments are not modeled"],
  ])("rejects %s anywhere in the value-import graph", async (_, imported, error) => {
    const p = registryControl("import { BASE } from './data.ts'; import { effect } from './effect.ts'; export function unused() { return effect; } export const CORPUS = BASE;\n", {
      "data.ts": "export const BASE = [{ id: 'BASE', kind: 'positive', location: 'fixture' }];\n",
      "effect.ts": `${imported}\n`,
      "nested.ts": "import { BASE } from './data.ts'; BASE.push({ id: 'SIDE', kind: 'positive', location: 'fixture' });\n",
    });
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain(error);
  });

  it("refuses imported native metadata as a registry membership selector", async () => {
    const p = registryControl("import { ROOT } from './effect.ts'; const BASE = { id: 'BASE', kind: 'positive', location: 'fixture' }; export const CORPUS = ROOT ? [BASE] : [{ ...BASE, id: 'SIDE' }];\n", {
      "effect.ts": "import { resolve } from 'node:path'; import { fileURLToPath } from 'node:url'; export const ROOT = resolve(fileURLToPath(import.meta.url), '..');\n",
    });
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain("native metadata cannot determine registry membership");
  });

  it.each([
    ["opaque field", "unknown"],
    ["opaque nested array/object", "[{ nested: { value: unknown } }]"],
    ["closure", "() => unknown"],
    ["Set", "new Set(['one'])"],
    ["RegExp", "/ready/"],
    ["undefined", "undefined"],
    ["nonfinite number", "1e309"],
    ["cyclic array", "cycle()"],
  ])("rejects selected record data containing %s before adapter consumption", async (_, expression) => {
    const p = registryControl(`import { unknown } from 'unresolved-package';
function cycle() { const values = []; values.push(values); return values; }
export const CORPUS = [{ id: 'BASE', kind: 'positive', location: 'fixture', metadata: ${expression} }];\n`);
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain("selected registry data CORPUS[0].metadata");
  });

  it("preserves shared acyclic selected-record data", async () => {
    const p = registryControl("const shared = { checks: ['ready'] }; export const CORPUS = [{ id: 'BASE', kind: 'positive', location: 'fixture', metadata: { first: shared, second: shared } }];\n");
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(0);
  });

  it.each([
    ["consumed module initializer", "const source = [BASE]; const earlier = source.map(entry => entry); const later = source.push(SIDE); export const CORPUS = later ? earlier : source;"],
    ["escaped factory array", "function seed() { return [BASE]; } const source = seed(); const earlier = source.map(entry => entry); const later = source.push(SIDE); export const CORPUS = later ? earlier : source;"],
    ["lazy module factory result", "function seed() { return [BASE]; } const source = seed(); function make() { source.push(SIDE); return source; } export const CORPUS = make();"],
    ["captured mutable factory state", "function seed() { const source = [BASE]; return () => { source.push(SIDE); return source; }; } const next = seed(); export const CORPUS = next();"],
  ])("rejects reordered mutations through %s", async (_, source) => {
    const p = registryControl(`const BASE = { id: 'BASE', kind: 'positive', location: 'fixture' }; const SIDE = { ...BASE, id: 'SIDE' }; ${source}\n`);
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain("array mutation must stay inside its active factory construction");
  });

  it("preserves nested factory-local array mutation in source order", async () => {
    const p = registryControl("const BASE = { id: 'BASE', kind: 'positive', location: 'fixture' }; function seed() { return [BASE]; } function make() { const local = seed(); local.push({ ...BASE, id: 'SIDE' }); return local; } export const CORPUS = make();\n");
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(0);
    const inventory = JSON.parse(readFileSync(p.inventory, "utf8")) as { reconciliations: { registry: string; members: { key: string }[] }[] };
    expect(inventory.reconciliations.find(row => row.registry === "CORPUS imported/spread entries")?.members.map(member => member.key)).toEqual(["BASE", "SIDE"]);
  });

  it.each(["export default function effect() { return true; }", "export default class effect {}"])("does not admit a named import from %s", async (source) => {
    const p = registryControl("import { effect } from './effect.ts'; export function unused() { return effect; } export const CORPUS = [{ id: 'BASE', kind: 'positive', location: 'fixture' }];\n", { "effect.ts": source });
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain("unresolved value import effect");
  });

  it.each([
    ["valid committed JSON", '{"version":1}', 0, ""],
    ["missing committed JSON", null, 1, "must resolve to retained text bytes"],
    ["non-data committed input", "export const sideEffect = 1;", 1, "Unexpected token"],
    ["gzip bytes rather than decoded JSON", gzipSync('{"version":1}'), 1, "Unexpected token"],
    ["false data admission", '{"version":2}', 1, "registry admission guard rejected"],
  ])("proves unused initialization only from %s", async (_, input, status, error) => {
    const p = registryControl("import { effect } from './effect.ts'; export function unused() { return effect; } export const CORPUS = [{ id: 'BASE', kind: 'positive', location: 'fixture' }];\n", {
      "effect.ts": "import { readFileSync } from 'node:fs'; const data = JSON.parse(readFileSync(new URL('./input.json', import.meta.url), 'utf8')); if (data.version !== 1) { throw new Error('invalid input'); } export function effect() { return data; }\n",
      ...(input === null ? {} : { "input.json": input }),
    });
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(status);
    if (status) expect(result.output).toContain(error);
    else {
      const inventory = JSON.parse(readFileSync(p.inventory, "utf8")) as { rows: { dependency: string; observedIdentity: unknown; declaredIdentity: unknown; state: string; assertionVenue: unknown }[] };
      expect(inventory.rows.find(row => row.dependency === "node:fs")).toMatchObject({ observedIdentity: null, declaredIdentity: "node:fs", state: "wholly-unbound", assertionVenue: null });
      // A host file that was not committed cannot repair missing snapshot input.
      p.git(["rm", "src/scan/input.json"]);
      p.git(["-c", "user.name=Census control", "-c", "user.email=census@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Remove snapshot input"]);
      writeFileSync(join(p.root, "src/scan/input.json"), '{"version":1}');
      const absent = await run(["--root", p.root, "--out", p.inventory]);
      expect(absent.status, absent.output).toBe(1);
      expect(absent.output).toContain("must resolve to retained text bytes");
    }
  });

  it("generates exact immutable normalized output and check mode preserves its bytes", async () => {
    const p = prepare();
    const first = await run(["--root", p.root, "--ref", p.head, "--out", p.inventory]);
    expect(first.status, first.output).toBe(0);
    const bytes = readFileSync(p.inventory, "utf8");
    const printed = await run(["--root", p.root, "--ref", p.head]);
    expect(printed.status, printed.output).toBe(0);
    expect(printed.output).toBe(bytes);
    const result = await run(["--root", p.root, "--check", "--inventory", p.inventory]);
    expect(result.status, result.output).toBe(0);
    expect(result.output).toContain("Completeness comparison passed");
    expect(result.output).toContain("unresolved");
    expect(readFileSync(p.inventory, "utf8")).toBe(bytes);
  });

  it("fails physical add/remove, new venue, hidden inline and supported-class directions", async () => {
    const p = prepare();
    const generated = await run(["--root", p.root, "--ref", p.head, "--out", p.inventory]);
    expect(generated.status, generated.output).toBe(0);
    const before = readFileSync(p.inventory, "utf8");
    const args = ["--root", p.root, "--check", "--inventory", p.inventory];
    writeFileSync(join(p.root, "unexpected.data"), "ordinary committed measurement = 1\n");
    const added = await run(args);
    expect(added.status, added.output).toBe(1);
    expect(added.output).toContain("unregistered-venue: unexpected.data");
    rmSync(join(p.root, "unexpected.data"));
    rmSync(join(p.root, "original-output"));
    const removed = await run(args);
    expect(removed.status, removed.output).toBe(1);
    expect(removed.output).toContain("removed-venue: original-output");
    p.git(["restore", "original-output"]);
    writeFileSync(join(p.root, "unrelated/ordinary.ts"), "export const x = 71;\nexport const obscure = 0.817;\n");
    const hidden = await run(args);
    expect(hidden.status, hidden.output).toBe(1);
    expect(hidden.output).toContain("changed-venue: unrelated/ordinary.ts");
    // An explicit old-ref check is archival, and must not be confused with current check.
    const archival = await run([...args, "--ref", p.head]);
    expect(archival.status, archival.output).toBe(0);
    p.git(["restore", "unrelated/ordinary.ts"]);
    writeFileSync(join(p.root, "unrelated/ordinary.ts"), "export const x = 71;\n// measured CPU model is unresolved\n");
    const hardware = await run(args);
    expect(hardware.status, hardware.output).toBe(1);
    expect(hardware.output).toContain("unregistered-dependency: unrelated/ordinary.ts#content-hint:hardware");
    expect(readFileSync(p.inventory, "utf8")).toBe(before);
  });

  it("rejects an unknown declared environment class even during generation", async () => {
    const p = prepare();
    writeFileSync(join(p.root, "unregistered-venue"), '{"environmentDependencyClass":"unknown-env-class"}\n');
    p.git(["add", "."]);
    p.git(["-c", "user.name=Census control", "-c", "user.email=census@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Add unknown class control"]);
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain("unregistered environment dependency class unknown-env-class");
  });

  it("refuses malformed inventories and an attempt to rewrite from check mode", async () => {
    const p = prepare(); writeFileSync(p.inventory, '{"schemaVersion":99}\n');
    const bad = await run(["--root", p.root, "--check", "--inventory", p.inventory]);
    expect(bad.status, bad.output).toBe(1);
    expect(bad.output).toContain("unsupported schemaVersion");
    const ambiguous = await run(["--root", p.root, "--check", "--out", p.inventory]);
    expect(ambiguous.status, ambiguous.output).toBe(1);
    expect(ambiguous.output).toContain("--check cannot rewrite");
    expect(readFileSync(p.inventory, "utf8")).toBe('{"schemaVersion":99}\n');
    const optionRef = await run(["--root", p.root, "--ref", "--help"]);
    expect(optionRef.status, optionRef.output).toBe(1);
  });
});
