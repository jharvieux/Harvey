import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
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

function run(args: string[]): Promise<{ status: number; output: string }> {
  return new Promise((done, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", CLI, ...args], { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
    child.stdout.on("data", (text: string) => { output += text; });
    child.stderr.on("data", (text: string) => { output += text; });
    child.once("error", reject);
    child.once("close", (status) => done({ status: status ?? 1, output }));
  });
}

describe("environment dependency shipping CLI (#1906)", () => {
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
