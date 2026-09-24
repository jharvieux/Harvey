import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createQualityScanTestHarness } from "./quality-scan-test-support.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function ownedTree() {
  const root = mkdtempSync(join(tmpdir(), "harvey-quality-lifecycle-"));
  roots.push(root);
  const fixture = mkdtempSync(join(root, "fixture-"));
  const pids = join(root, "pids.json");
  const receipts = join(root, "terminated.jsonl");
  const record = (role: string) => `fs.appendFileSync(${JSON.stringify(receipts)},JSON.stringify({role:${JSON.stringify(role)},fixturePresent:fs.existsSync(${JSON.stringify(fixture)})})+'\\n')`;
  const child = `const fs=require('node:fs');process.on('SIGTERM',()=>${record("descendant")});process.stderr.write('READY');setInterval(()=>{},1000);`;
  const script = join(root, "tree.cjs");
  writeFileSync(script, `const fs=require('node:fs');const {spawn}=require('node:child_process');
const child=spawn(process.execPath,['-e',${JSON.stringify(child)}],{stdio:['ignore','ignore','pipe']});
fs.writeFileSync(${JSON.stringify(pids)},JSON.stringify([process.pid,child.pid]));
process.on('SIGTERM',()=>${record("parent")});child.stderr.pipe(process.stderr);setInterval(()=>{},1000);`);
  const readPids = () => existsSync(pids) ? JSON.parse(readFileSync(pids, "utf8")) as number[] : [];
  const forceStop = () => { for (const pid of readPids().reverse()) { try { process.kill(pid, "SIGKILL"); } catch { /* Already reaped. */ } } };
  return { root, fixture, script, receipts, readPids, forceStop };
}

async function expectReaped(pids: number[]) {
  const running = (pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } };
  for (let attempt = 0; attempt < 40 && pids.some(running); attempt += 1) await new Promise((done) => setTimeout(done, 25));
  expect(pids).toHaveLength(2);
  expect(pids.filter(running)).toEqual([]);
}

describe("quality CLI child ownership (#2177)", () => {
  it("preserves successful stderr bytes and nonzero native diagnostics", async () => {
    const harness = createQualityScanTestHarness();
    try {
      expect(await harness.run(process.execPath, ["-e", "const b=Buffer.from('🪴');process.stderr.write(b.subarray(0,2));setTimeout(()=>process.stderr.write(b.subarray(2)),20);"], process.cwd())).toBe("🪴");
      await expect(harness.run(process.execPath, ["-e", "process.stderr.write('specific failure\\n');process.exitCode=7;"], process.cwd())).rejects.toMatchObject({ exitCode: 7, state: "exited", stderr: "specific failure\n" });
    } finally { await harness.cleanup(); }
  });

  it("distinguishes a startup failure from a child exit", async () => {
    const harness = createQualityScanTestHarness();
    try {
      await expect(harness.run("/harvey-nonexistent-quality-child", [], process.cwd())).rejects.toMatchObject({ state: "spawn-error", message: expect.stringContaining("ENOENT") });
    } finally { await harness.cleanup(); }
  });

  it("preserves stdin bytes and permits argument rejection before held-open stdin", async () => {
    const harness = createQualityScanTestHarness();
    try {
      const text = "reason 🪴\nwith whitespace \t";
      expect(await harness.run(process.execPath, ["-e", "process.stdin.pipe(process.stderr);"], process.cwd(), text)).toBe(text);
      await expect(harness.run(process.execPath, ["-e", "process.stderr.write('usage first');process.exitCode=2;"], process.cwd(), null)).rejects.toMatchObject({ exitCode: 2, state: "exited", stderr: "usage first" });
    } finally { await harness.cleanup(); }
  });

  it("times out a ready parent and pipe-holding descendant before fixture removal", async () => {
    const tree = ownedTree();
    const harness = createQualityScanTestHarness({ timeoutMs: 1_500, killGraceMs: 100 });
    harness.dirs.push(tree.fixture);
    let observedReady = false;
    try {
      const result = await harness.run(process.execPath, [tree.script], tree.root, undefined, { onFirstByte: () => { observedReady = true; } }).catch((error: Error) => error);
      expect(observedReady).toBe(true);
      expect(result).toMatchObject({ state: "timed-out" });
      await expectReaped(tree.readPids());
      expect(existsSync(tree.fixture)).toBe(true);
      await harness.cleanup();
      expect(existsSync(tree.fixture)).toBe(false);
      expect(readFileSync(tree.receipts, "utf8").trim().split("\n").map((line) => JSON.parse(line))).toEqual(expect.arrayContaining([
        { role: "parent", fixturePresent: true }, { role: "descendant", fixturePresent: true },
      ]));
    } finally { tree.forceStop(); await harness.cleanup(); }
  });

  it("aborts an outstanding invocation when outer teardown begins and awaits close before deleting its fixture", async () => {
    const tree = ownedTree();
    const harness = createQualityScanTestHarness({ timeoutMs: 5_000, killGraceMs: 100 });
    harness.dirs.push(tree.fixture);
    let ready!: () => void;
    const firstByte = new Promise<void>((done) => { ready = done; });
    const invocation = harness.run(process.execPath, [tree.script], tree.root, undefined, { onFirstByte: ready }).catch((error: Error) => error);
    try {
      await firstByte;
      await harness.cleanup();
      expect(await invocation).toMatchObject({ state: "aborted" });
      await expectReaped(tree.readPids());
      expect(existsSync(tree.fixture)).toBe(false);
      expect(readFileSync(tree.receipts, "utf8").trim().split("\n").map((line) => JSON.parse(line))).toEqual(expect.arrayContaining([
        { role: "parent", fixturePresent: true }, { role: "descendant", fixturePresent: true },
      ]));
    } finally { tree.forceStop(); await harness.cleanup(); }
  });
});
