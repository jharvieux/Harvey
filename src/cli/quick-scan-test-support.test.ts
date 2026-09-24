import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createQuickScanTestHarness } from "./quick-scan-test-support.js";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function processTree() {
  const dir = mkdtempSync(join(tmpdir(), "harvey-quick-lifecycle-"));
  dirs.push(dir);
  const fixture = mkdtempSync(join(dir, "fixture-"));
  const receipt = join(dir, "termination.jsonl");
  const pids = join(dir, "pids.json");
  const descendant = `const fs=require('node:fs');
process.on('SIGTERM',()=>fs.appendFileSync(${JSON.stringify(receipt)},JSON.stringify({role:'descendant',fixturePresent:fs.existsSync(${JSON.stringify(fixture)})})+'\\n'));
process.stdout.write('READY\\n'); setInterval(()=>{},1000);`;
  const source = `const fs=require('node:fs');const {spawn}=require('node:child_process');
const child=spawn(process.execPath,['-e',${JSON.stringify(descendant)}],{stdio:['ignore','pipe','inherit']});
fs.writeFileSync(${JSON.stringify(pids)},JSON.stringify([process.pid,child.pid]));
process.on('SIGTERM',()=>fs.appendFileSync(${JSON.stringify(receipt)},JSON.stringify({role:'parent',fixturePresent:fs.existsSync(${JSON.stringify(fixture)})})+'\\n'));
child.stdout.pipe(process.stdout);setInterval(()=>{},1000);`;
  const script = join(dir, "tree.cjs");
  writeFileSync(script, source);
  return { fixture, receipt, pids, script };
}

async function expectStopped(pidsPath: string) {
  const pids = JSON.parse(readFileSync(pidsPath, "utf8")) as number[];
  const running = (pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } };
  // A killed descendant can need a short scheduler turn to be reaped by its new parent.
  for (let attempt = 0; attempt < 20 && pids.some(running); attempt += 1) {
    await new Promise((done) => setTimeout(done, 25));
  }
  expect(pids.filter(running)).toEqual([]);
}

describe("quick-scan child ownership", () => {
  it("keeps the event loop responsive after the first byte and decodes complete UTF-8", async () => {
    const harness = createQuickScanTestHarness({ timeoutMs: 3_000 });
    let observed = false;
    let ticks = 0;
    const heartbeat = setInterval(() => { if (observed) ticks += 1; }, 10);
    try {
      const result = await harness.run(["-e", "process.stdout.write('READY ');const b=Buffer.from('🪴');process.stdout.write(b.subarray(0,2));setTimeout(()=>process.stdout.write(b.subarray(2)),150);"], () => { observed = true; });
      expect(result.stdout).toBe("READY 🪴");
      expect(ticks).toBeGreaterThan(5);
    } finally { clearInterval(heartbeat); await harness.cleanup(); }
  });

  it("ends a timed-out parent and its TERM-resistant descendant before fixture cleanup", async () => {
    const tree = processTree();
    const harness = createQuickScanTestHarness({ timeoutMs: 1_200, killGraceMs: 100 });
    harness.dirs.push(tree.fixture);
    let firstByte = 0;
    try {
      await expect(harness.run([tree.script], () => { firstByte = performance.now(); })).rejects.toThrow("timed-out");
      expect(firstByte).toBeGreaterThan(0);
      expect(performance.now() - firstByte).toBeLessThan(2_000);
      await expectStopped(tree.pids);
      expect(existsSync(tree.fixture)).toBe(true);
      expect(readFileSync(tree.receipt, "utf8").trim().split("\n").map((line) => JSON.parse(line))).toEqual(expect.arrayContaining([
        { role: "parent", fixturePresent: true }, { role: "descendant", fixturePresent: true },
      ]));
    } finally { await harness.cleanup(); }
    expect(existsSync(tree.fixture)).toBe(false);
  });

  it("cancels and awaits every owned group when an outer test ends early", async () => {
    const tree = processTree();
    const harness = createQuickScanTestHarness({ timeoutMs: 3_000, killGraceMs: 100 });
    harness.dirs.push(tree.fixture);
    let ready!: () => void;
    const firstByte = new Promise<void>((done) => { ready = done; });
    const result = harness.run([tree.script], ready).catch((error: Error) => error);
    try {
      await firstByte;
      await harness.cleanup();
      expect(await result).toMatchObject({ message: expect.stringContaining("aborted") });
      await expectStopped(tree.pids);
      expect(existsSync(tree.fixture)).toBe(false);
      expect(readFileSync(tree.receipt, "utf8").trim().split("\n").map((line) => JSON.parse(line))).toEqual(expect.arrayContaining([
        { role: "parent", fixturePresent: true }, { role: "descendant", fixturePresent: true },
      ]));
    } finally { await harness.cleanup(); }
  });

  it("reports a bounded stderr tail when a real invocation fails", async () => {
    const harness = createQuickScanTestHarness();
    try {
      const error = await harness.run(["-e", "process.stderr.write('x'.repeat(20000)+'specific-failure');process.exitCode=9;"]).catch((cause: Error) => cause);
      expect(error).toMatchObject({ message: expect.stringContaining("exit 9") });
      expect(error).toMatchObject({ message: expect.stringContaining("specific-failure") });
      expect((error as Error).message.length).toBeLessThan(17_000);
    } finally { await harness.cleanup(); }
  });
});
