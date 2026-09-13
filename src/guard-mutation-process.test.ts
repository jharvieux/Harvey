import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runGuardCommand } from "./guard-mutation-process.js";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function fixture(source: string) {
  const dir = mkdtempSync(join(tmpdir(), "harvey-guard-process-")); dirs.push(dir);
  const script = join(dir, "child.cjs"); writeFileSync(script, source);
  return { dir, options: { command: [process.execPath, script], cwd: dir, bundleDir: dir, outputPrefix: "child", timeoutMs: 5_000, killGraceMs: 150 } };
}

describe("isolated guard processes and first-byte responsiveness", () => {
  it("services the parent event loop while a real child waits; anchors latency to the child's first byte", async () => {
    const p = fixture("process.stdout.write('READY '+Date.now()+'\\n'); setTimeout(()=>process.stdout.write('DONE\\n'), 800);");
    let firstByteObserved = 0; let ticksAfterByte = 0;
    const heartbeat = setInterval(() => { if (firstByteObserved) ticksAfterByte++; }, 20);
    try {
      const result = await runGuardCommand({ ...p.options, onFirstByte: () => { firstByteObserved = Date.now(); } });
      const childFirstByte = Number(/READY (\d+)/.exec(result.stdout.tail)?.[1]);
      expect(result.state).toBe("exited"); expect(result.exitCode).toBe(0);
      expect(childFirstByte).toBeGreaterThan(0);
      // A synchronous process call observes READY only after the 800ms child has finished.
      expect(firstByteObserved - childFirstByte).toBeLessThan(500);
      expect(ticksAfterByte).toBeGreaterThan(10);
      expect(result.fromFirstByteMs).toBeGreaterThan(700);
      expect(result.maxParentBlockMs).toBeLessThan(500);
      expect(result.stdout.bytes).toBe(readFileSync(join(p.dir, "child.stdout.log")).length);
    } finally { clearInterval(heartbeat); }
  });

  it("retains complete output and bounded tails for a failed child", async () => {
    const p = fixture("process.stdout.write('x'.repeat(60000)); process.stderr.write('distinct-shard-cause\\n'); process.exitCode=9;");
    const result = await runGuardCommand(p.options);
    expect(result.exitCode).toBe(9); expect(result.stdout.bytes).toBe(60000);
    expect(Buffer.byteLength(result.stdout.tail)).toBe(16 * 1024);
    expect(result.stderr.tail).toContain("distinct-shard-cause");
    expect(readFileSync(join(p.dir, "child.stdout.log")).length).toBe(60000);
  });

  it("times out a silent process and kills its independently running descendant", async () => {
    const p = fixture(`const {spawn}=require('node:child_process'); const fs=require('node:fs');
const child=spawn(process.execPath,['-e',"setInterval(()=>{},1000)"],{stdio:'ignore'});
fs.writeFileSync('descendant.pid',String(child.pid)); process.on('SIGTERM',()=>{}); setInterval(()=>{},1000);`);
    const result = await runGuardCommand({ ...p.options, timeoutMs: 350 });
    expect(result.state).toBe("timed-out"); expect(result.firstByteAt).toBeNull();
    expect(result.terminationAcknowledged).toBe(true); expect(result.elapsedMs).toBeLessThan(2_000);
    const pid = Number(readFileSync(join(p.dir, "descendant.pid"), "utf8"));
    expect(() => process.kill(pid, 0)).toThrow();
  });

  it("records cancellation and a missing executable as terminal results", async () => {
    const p = fixture("process.stdout.write('READY\\n'); setInterval(()=>{},1000);");
    const abort = new AbortController();
    const result = await runGuardCommand({ ...p.options, signal: abort.signal, onFirstByte: () => abort.abort() });
    expect(result.state).toBe("aborted"); expect(result.terminationAcknowledged).toBe(true);
    const missing = await runGuardCommand({ ...p.options, command: [join(p.dir, "absent")], outputPrefix: "absent" });
    expect(missing.state).toBe("spawn-error"); expect(missing.error).toContain("ENOENT");
  });
});
