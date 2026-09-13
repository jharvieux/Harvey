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
  for (const [path, text] of Object.entries(siblings)) {
    const file = join(p.root, "src/scan", path); mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, text);
  }
  p.git(["add", "."]);
  p.git(["-c", "user.name=Census control", "-c", "user.email=census@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Add registry evaluation control"]);
  return p;
}

describe("environment dependency shipping CLI (#1906)", () => {
  it.each([
    ["function declaration", "function make(this: void, tier: string) { return [{ ...BASE, expectedTier: tier ?? 'review' }]; } export const CORPUS = make('local');"],
    ["overload implementation", "function make(this: void, tier: string): unknown[]; function make(this: void, tier: string) { return [{ ...BASE, expectedTier: tier ?? 'review' }]; } export const CORPUS = make('local');"],
    ["function expression", "const make = function(this: void, tier: string) { return [{ ...BASE, expectedTier: tier ?? 'review' }]; }; export const CORPUS = make('local');"],
    ["destructured runtime parameter", "function make(this: void, { tier }: { tier: string }) { return [{ ...BASE, expectedTier: tier }]; } export const CORPUS = make({ tier: 'local' });"],
    ["extra runtime arguments", "function make(this: void, tier: string) { return [{ ...BASE, expectedTier: tier ?? 'review' }]; } export const CORPUS = make('local', 'review');"],
    ["missing runtime argument", "function make(this: void, tier?: string) { return [{ ...BASE, expectedTier: tier ?? 'review' }]; } export const CORPUS = make();"],
    ["map callback positions", "export const CORPUS = ['local'].map(function(this: void, tier, index, input) { return { ...BASE, id: index === 0 && input[0] === tier ? 'OWNED' : 'OTHER', expectedTier: tier }; });"],
    ["flatMap callback positions", "export const CORPUS = ['local'].flatMap(function(this: void, tier, index) { return [{ ...BASE, id: index === 0 ? 'OWNED' : 'OTHER', expectedTier: tier }]; });"],
    ["filter callback positions", "const tiers = ['local'].filter(function(this: void, tier) { return tier === 'local'; }); export const CORPUS = [{ ...BASE, expectedTier: tiers[0] ?? 'review' }];"],
    ["some callback positions", "function make() { const rows = []; ['local', 'review'].some(function(this: void, tier, index) { rows.push({ ...BASE, id: index === 0 ? 'OWNED' : 'OTHER', expectedTier: tier }); return true; }); return rows; } export const CORPUS = make();"],
  ])("preserves runtime argument positions after this erasure for %s", async (_, source) => {
    const p = registryControl(`const BASE = { id: 'OWNED', kind: 'positive', location: 'fixture' };
export const LIVE_TIERS = ['local', 'connected', 'hosted'];
export function mechanicalCorpus(corpus) { return corpus.filter((e) => e.module === undefined); }
${source}\n`, { "../cli/validate-calibration.ts": "import { CORPUS, mechanicalCorpus } from '../scan/calibration.ts'; const scoredCorpus = mechanicalCorpus(CORPUS);\n" });
    const oracle = await runNode(["--import", "tsx", "--input-type=module", "--eval", `const { CORPUS } = await import(${JSON.stringify(pathToFileURL(join(p.root, "src/scan/calibration.ts")).href)}); const { mechanicalCorpus, buildCoverageMatrix } = await import(${JSON.stringify(pathToFileURL(join(ROOT, "src/scan/calibration.ts")).href)}); console.log(JSON.stringify({ members: CORPUS.map(row => row.id), scored: buildCoverageMatrix([], mechanicalCorpus(CORPUS)).rows.filter(row => !row.notScored).map(row => row.id) }));`]);
    expect(oracle.status, oracle.output).toBe(0);
    const actual = JSON.parse(oracle.output) as { members: string[]; scored: string[] };
    expect(actual.members).toEqual(["OWNED"]);
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(0);
    const inventory = JSON.parse(readFileSync(p.inventory, "utf8")) as { rows: { id: string; evidence: { anchor: string }; assertionVenue: unknown }[] };
    const rows = inventory.rows.filter(row => row.id.includes("#CORPUS/"));
    expect(rows.map(row => row.evidence.anchor.replace("CORPUS/", ""))).toEqual(actual.members);
    expect(rows.filter(row => row.assertionVenue).map(row => row.evidence.anchor.replace("CORPUS/", ""))).toEqual(actual.scored);
  });

  it.each([
    ["runtime default", "function make(this: void, tier = 'local') { return [BASE]; } export const CORPUS = make();", 0, "factory rest/default parameters are not modeled"],
    ["runtime rest", "function make(this: void, ...tiers: string[]) { return [BASE]; } export const CORPUS = make('local');", 0, "factory rest/default parameters are not modeled"],
    ["duplicate runtime names", "function make(this: void, tier, tier) { return [BASE]; } export const CORPUS = make();", 1, "duplicate lexical binding tier"],
    ["misplaced erased parameter", "function make(tier: string, this: void) { return [BASE]; } export const CORPUS = make('local');", 0, "erased this parameter shape is not modeled"],
    ["arrow erased parameter", "const make = (this: void, tier: string) => [BASE]; export const CORPUS = make('local');", 1, "erased this parameter shape is not modeled"],
    ["defaulted erased parameter", "function make(this: void = undefined, tier: string) { return [BASE]; } export const CORPUS = make('local');", 1, "registry source has unresolved parser diagnostics"],
  ])("keeps this erasure within the supported grammar for %s", async (_, source, nativeExit, error) => {
    const p = registryControl(`const BASE = { id: 'OWNED', kind: 'positive', location: 'fixture' }; ${source}\n`);
    const oracle = await runNode(["--import", "tsx", "--input-type=module", "--eval", `await import(${JSON.stringify(pathToFileURL(join(p.root, "src/scan/calibration.ts")).href)});`]);
    expect(oracle.status, oracle.output).toBe(nativeExit);
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain(error);
  });

  it.each([
    ["module constants", "const tier = 'local'; const \\u0074ier = 'review'; export const CORPUS = [BASE];", 1],
    ["class and constant", "class tier {} const \\u0074ier = 'review'; export const CORPUS = [BASE];", 1],
    ["function declarations", "function tier() { return 'local'; } function \\u0074ier() { return 'review'; } export const CORPUS = [BASE];", 1],
    ["function and constant", "function tier() { return 'local'; } const \\u0074ier = 'review'; export const CORPUS = [BASE];", 1],
    ["value import and constant", "import { tier } from './dep.ts'; const \\u0074ier = 'review'; export const CORPUS = [{ ...BASE, expectedTier: tier }];", 0],
    ["called factory parameters", "function make(tier, \\u0074ier) { return [BASE]; } export const CORPUS = make('local', 'review');", 1],
    ["unused factory parameters", "function unused(tier, \\u0074ier) { return tier; } export const CORPUS = [BASE];", 1],
    ["destructured parameters", "function make({ a: tier }, { b: \\u0074ier }) { return [BASE]; } export const CORPUS = make({ a: 1 }, { b: 2 });", 1],
    ["local destructuring", "function make() { const { a: tier, b: \\u0074ier } = { a: 1, b: 2 }; return [BASE]; } export const CORPUS = make();", 1],
    ["parameter and local", "function make(tier) { const \\u0074ier = 'review'; return [BASE]; } export const CORPUS = make('local');", 1],
  ])("rejects canonical binding collisions between %s", async (_, source, nativeExit) => {
    const p = registryControl(`const BASE = { id: 'OWNED', kind: 'positive', location: 'fixture' }; ${source}\n`, { "dep.ts": "export const tier = 'local';\n" });
    const oracle = await runNode(["--import", "tsx", "--input-type=module", "--eval", `const { CORPUS } = await import(${JSON.stringify(pathToFileURL(join(p.root, "src/scan/calibration.ts")).href)}); console.log(JSON.stringify(CORPUS));`]);
    expect(oracle.status, oracle.output).toBe(nativeExit);
    if (nativeExit) expect(oracle.output).toMatch(/already been declared|cannot be bound multiple times/);
    else expect(JSON.parse(oracle.output)[0]).toMatchObject({ expectedTier: "review" });
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain("duplicate lexical binding tier");
  });

  it.each([
    ["duplicate object keys", "export const CORPUS = [{ ...BASE, id: 'OLD', '\\u0069d': 'OWNED' }];"],
    ["duplicate canonical numeric keys", "const keys = { 16: 'OLD', 0x10: 'OWNED' }; export const CORPUS = [{ ...BASE, id: keys[16] }];"],
    ["separate factory scopes", "function make() { const id = 'OWNED'; return { ...BASE, id }; } function other() { const id = 'OTHER'; return id; } export const CORPUS = [make()];"],
    ["distinct destructuring names for one key", "function make({ id: first, id: second }) { return [{ ...BASE, id: first === second ? first : 'OTHER' }]; } export const CORPUS = make({ id: 'OWNED' });"],
    ["erased type and value names", "interface id { value: string } const id = 'OWNED'; export const CORPUS = [{ ...BASE, id }];"],
    ["erased import and value names", "import type { id } from './types.ts'; const id = 'OWNED'; export const CORPUS = [{ ...BASE, id }];"],
    ["erased function overloads", "function make(value: string): unknown[]; function make(value: number): unknown[]; function make(value: unknown) { return [BASE]; } export const CORPUS = make(1);"],
  ])("preserves valid canonical binding scopes for %s", async (_, source) => {
    const p = registryControl(`const BASE = { id: 'OWNED', kind: 'positive', location: 'fixture' }; ${source}\n`, { "types.ts": "export interface id { value: string }\n" });
    const oracle = await runNode(["--import", "tsx", "--input-type=module", "--eval", `const { CORPUS } = await import(${JSON.stringify(pathToFileURL(join(p.root, "src/scan/calibration.ts")).href)}); console.log(JSON.stringify(CORPUS.map(row => row.id)));`]);
    expect(oracle.status, oracle.output).toBe(0);
    expect(JSON.parse(oracle.output)).toEqual(["OWNED"]);
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(0);
    const inventory = JSON.parse(readFileSync(p.inventory, "utf8")) as { reconciliations: { registry: string; members: { key: string }[] }[] };
    expect(inventory.reconciliations.find(row => row.registry === "CORPUS imported/spread entries")?.members.map(member => member.key)).toEqual(["OWNED"]);
  });

  it.each([
    ["Unicode string tier", "", "'\\u0065xpectedTier': 'local'"],
    ["Unicode string module", "", "'\\u006dodule': 'M6'"],
    ["hexadecimal string module", "", "'\\x6dodule': 'M6'"],
    ["code-point string module", "", "'\\u{6d}odule': 'M6'"],
    ["escaped identifier module", "", "\\u006dodule: 'M6'"],
    ["escaped shorthand binding", "const \\u006dodule = 'M6';", "\\u006dodule"],
    ["escaped destructuring property", "function make() { const { '\\u006dodule': tag } = { module: 'M6' }; return tag; }", "module: make()"],
    ["escaped destructuring shorthand", "function make() { const { \\u006dodule } = { module: 'M6' }; return module; }", "module: make()"],
    ["numeric destructuring property", "function make() { const { 0x10: tag } = { 16: 'M6' }; return tag; }", "module: make()"],
    ["hexadecimal numeric key", "", "module: { 0x10: 'M6' }[16]"],
    ["exponent numeric key", "", "module: { 1e2: 'M6' }[100]"],
    ["separator numeric key", "", "module: { 1_000: 'M6' }[1000]"],
    ["escaped numeric-looking string key", "", "module: { '\\x31e2': 'M6' }['1e2']"],
    ["allowed prototype-like key", "", "module: { '\\u0063onstructorValue': 'M6' }.constructorValue"],
  ])("decodes record keys for %s before assigning scorer ownership", async (_, declarations, properties) => {
    const p = registryControl(`export const LIVE_TIERS = ['local', 'connected', 'hosted'];
export function mechanicalCorpus(corpus) { return corpus.filter((e) => e.module === undefined); }
${declarations}
export const CORPUS = [{ id: 'OWNED', kind: 'positive', location: 'fixture', ${properties} }];\n`, {
      "../cli/validate-calibration.ts": "import { CORPUS, mechanicalCorpus } from '../scan/calibration.ts'; const scoredCorpus = mechanicalCorpus(CORPUS);\n",
    });
    const oracle = await runNode(["--import", "tsx", "--input-type=module", "--eval", `const { CORPUS } = await import(${JSON.stringify(pathToFileURL(join(p.root, "src/scan/calibration.ts")).href)}); const { mechanicalCorpus, buildCoverageMatrix } = await import(${JSON.stringify(pathToFileURL(join(ROOT, "src/scan/calibration.ts")).href)}); console.log(JSON.stringify({ members: CORPUS.map(entry => entry.id), scored: buildCoverageMatrix([], mechanicalCorpus(CORPUS)).rows.filter(row => !row.notScored).map(row => row.id) }));`]);
    expect(oracle.status, oracle.output).toBe(0);
    expect(JSON.parse(oracle.output)).toEqual({ members: ["OWNED"], scored: [] });
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(0);
    const inventory = JSON.parse(readFileSync(p.inventory, "utf8")) as { rows: { id: string; assertionVenue: unknown }[] };
    const members = inventory.rows.filter(row => row.id.includes("#CORPUS/"));
    expect(members).toHaveLength(1);
    expect(members[0]).toMatchObject({ assertionVenue: null });
  });

  it.each([
    ["escaped prototype setter", "", "'\\u005f_proto__': {}"],
    ["escaped constructor", "", "'\\u0063onstructor': {}"],
    ["escaped prototype name", "", "\\u0070rototype: {}"],
    ["escaped prototype shorthand", "const __proto__ = {};", "\\u005f_proto__"],
    ["escaped binding prototype access", "function make() { const { '\\u0063onstructor': value } = {}; return value ? 'SIDE' : 'OWNED'; }", "id: make()"],
    ["unmodeled computed property", "", "['module']: 'M6'"],
    ["unmodeled bigint property", "", "1n: 'M6'"],
  ])("rejects unsafe or unsupported record keys: %s", async (_, declarations, properties) => {
    const p = registryControl(`${declarations} export const CORPUS = [{ id: 'OWNED', kind: 'positive', location: 'fixture', ${properties} }];\n`);
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toMatch(/prototype (property|access)|property name .* is not modeled|computed property is not modeled/);
  });

  it.each([
    ["forward module constant", "export const CORPUS = rows; const rows = [BASE];", {}],
    ["factory called before module constant", "function make() { return rows; } export const CORPUS = make(); const rows = [BASE];", {}],
    ["cached later constant", "const early = make(); const later = [BASE]; function make() { return later; } export const CORPUS = later.length ? early : later;", {}],
    ["cached admission guard input", "if (later) { throw new Error('invalid'); } const later = false; export const CORPUS = later ? [] : [BASE];", {}],
    ["same-statement constant order", "const early = later, later = [BASE]; export const CORPUS = later.length ? early : later;", {}],
    ["local forward shadow", "const rows = [BASE]; function make() { const early = rows; const rows = [SIDE]; return early; } export const CORPUS = make();", {}],
    ["local self shadow", "const rows = [BASE]; function make() { const rows = rows; return rows; } export const CORPUS = make();", {}],
    ["local shadow after return", "const rows = [BASE]; function make() { return rows; const rows = [SIDE]; } export const CORPUS = make();", {}],
    ["local closure called before shadow initialization", "const rows = [BASE]; function make() { const read = () => rows; const early = read(); const rows = [SIDE]; return early; } export const CORPUS = make();", {}],
    ["for-of input shadow", "const rows = [[BASE]]; function make() { for (const rows of rows) { return rows; } } export const CORPUS = make();", {}],
    ["imported forward initializer", "import { make } from './dep.ts'; export const CORPUS = make();", { "dep.ts": "const rows = later; const later = [{ id: 'BASE', kind: 'positive', location: 'fixture' }]; export function make() { return rows; }" }],
    ["eager cyclic import", "import { make } from './dep.ts'; export const rows = [BASE]; export const CORPUS = make();", { "dep.ts": "import { rows } from './calibration.ts'; const early = rows; export function make() { return early; }" }],
  ])("enforces lexical readiness for %s", async (_, source, siblings) => {
    const p = registryControl(`const BASE = { id: 'BASE', kind: 'positive', location: 'fixture' }; const SIDE = { ...BASE, id: 'SIDE' }; ${source}\n`, siblings);
    const oracle = await runNode(["--input-type=module", "--eval", `await import(${JSON.stringify(pathToFileURL(join(p.root, "src/scan/calibration.ts")).href)});`]);
    expect(oracle.status, oracle.output).toBe(1);
    expect(oracle.output).toContain("ReferenceError");
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain("before initialization");
  });

  it.each([
    ["hoisted function", "export const CORPUS = make(); function make() { return [BASE]; }", {}],
    ["earlier same-statement constant", "const earlier = [BASE], later = earlier; export const CORPUS = later;", {}],
    ["deferred local closure", "function make() { const read = () => rows; const rows = [BASE]; return read(); } export const CORPUS = make();", {}],
    ["for-of body shadow", "function make() { for (const rows of [[SIDE]]) { const rows = [BASE]; return rows; } } export const CORPUS = make();", {}],
    ["initialized dependency factory", "import { make } from './dep.ts'; export const CORPUS = make();", { "dep.ts": "export function make() { return rows; } const rows = [{ id: 'BASE', kind: 'positive', location: 'fixture' }];" }],
    ["deferred cyclic import", "import { make } from './dep.ts'; export const rows = [BASE]; export const CORPUS = make();", { "dep.ts": "import { rows } from './calibration.ts'; export function make() { return rows; }" }],
  ])("preserves lexical readiness for %s", async (_, source, siblings) => {
    const p = registryControl(`const BASE = { id: 'BASE', kind: 'positive', location: 'fixture' }; const SIDE = { ...BASE, id: 'SIDE' }; ${source}\n`, siblings);
    const oracle = await runNode(["--input-type=module", "--eval", `const { CORPUS } = await import(${JSON.stringify(pathToFileURL(join(p.root, "src/scan/calibration.ts")).href)}); console.log(JSON.stringify(CORPUS.map(entry => entry.id).sort()));`]);
    expect(oracle.status, oracle.output).toBe(0);
    const result = await run(["--root", p.root, "--out", p.inventory]);
    expect(result.status, result.output).toBe(0);
    const inventory = JSON.parse(readFileSync(p.inventory, "utf8")) as { reconciliations: { registry: string; members: { key: string }[] }[] };
    expect(inventory.reconciliations.find(row => row.registry === "CORPUS imported/spread entries")?.members.map(member => member.key)).toEqual(JSON.parse(oracle.output));
  });

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
      // This control retains a host-only file while requiring the missing committed input to reject.
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
