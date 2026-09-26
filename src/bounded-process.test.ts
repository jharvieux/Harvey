import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { admitReadinessStage, bindReadinessPlanV1, createReadinessAdmission, type ReadinessSpawnRequest } from "./audit-readiness-authority.js";
import { discoverReadinessPlan } from "./audit-readiness.js";
import { type BoundedProcessOptions, type BoundedProcessRedactor, type BoundedProcessResult } from "./bounded-process.js";
import { createBoundedProcessRunner } from "../test-fixtures/readiness-native-process-group.js";
import { captureSourceSentinel, cleanupDisposableTarget, createDisposableTarget } from "./disposable-target.js";

const roots: string[] = [];
const pids = new Set<number>();
const identity: BoundedProcessRedactor = (text) => text;
const defaults: BoundedProcessOptions = { timeoutMs: 5_000, killGraceMs: 100, closeGraceMs: 800, redact: identity };

afterEach(async () => {
  for (const root of roots) {
    for (const name of ["descendant.pid", "escaped.pid"]) {
      try { pids.add(Number(await readFile(join(root, name), "utf8"))); } catch { /* A fixture can fail before its child starts. */ }
    }
  }
  for (const pid of pids) {
    try { process.kill(-pid, "SIGKILL"); } catch { /* Already reaped. */ }
    try { process.kill(pid, "SIGKILL"); } catch { /* Already reaped. */ }
  }
  pids.clear();
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

async function fixture(source: string, env: Record<string, string> = {}, args: string[] = []) {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "harvey-bounded-process-")));
  roots.push(dir);
  const script = join(dir, "child with spaces.cjs");
  await writeFile(script, source);
  const request = { bin: process.execPath, args: Object.freeze([script, ...args]), cwd: dir, shell: false as const } as ReadinessSpawnRequest;
  Object.defineProperty(request, "env", { value: Object.freeze({ PATH: dirname(process.execPath), ...env }), enumerable: false });
  return { dir, request: Object.freeze(request) };
}

async function run(request: ReadinessSpawnRequest, options: Partial<BoundedProcessOptions> = {}): Promise<BoundedProcessResult> {
  const result = await createBoundedProcessRunner().run(request, { ...defaults, ...options });
  if (result.pid !== null) pids.add(result.pid);
  return result;
}

function digest(value: string): string { return createHash("sha256").update(value).digest("hex"); }

function assertNoProcess(pid: number): void {
  expect(() => process.kill(pid, 0)).toThrow();
}

describe.skipIf(process.platform === "win32")("bounded readiness child lifecycle", () => {
  it("runs the exact B1 admitted command in its disposable copy and preserves the source", async () => {
    const { dir } = await fixture("");
    const source = join(dir, "source");
    const scratch = join(dir, "scratch");
    await mkdir(source); await mkdir(scratch);
    await writeFile(join(source, "package.json"), JSON.stringify({ name: "bounded-fixture", version: "1.0.0", packageManager: "npm@10.9.2", scripts: { test: "node check.cjs" } }));
    await writeFile(join(source, "check.cjs"), "require('node:fs').writeFileSync('executed', process.cwd()); process.stdout.write('ADMITTED\\n');");
    const before = await captureSourceSentinel(source);
    const plan = discoverReadinessPlan(source);
    const created = await createDisposableTarget(source, { tempParent: scratch });
    expect(created.status).toBe("ready");
    if (created.status !== "ready") throw new Error("fixture disposable creation failed");
    const stage = plan.stages.find((row) => row.kind === "test")!;
    const context = createReadinessAdmission(plan, bindReadinessPlanV1(plan, before), {
      allowTargetInstall: false, approvedEnvNames: [], environment: {},
      stageAuthorizations: [{ stageId: stage.id, effect: "disposable-local", source: "fixture operator", reason: "The exact test writes only in the copy.", falsifier: "An original file changes." }],
    });
    const admission = await admitReadinessStage(context, stage.id, created.target);
    expect(admission.status).toBe("admitted");
    if (admission.status !== "admitted") throw new Error("fixture was not admitted");
    try {
      const result = await run(admission.request);
      expect(result.succeeded).toBe(true);
      expect(result.stdout.head).toContain("ADMITTED");
      expect(await readFile(join(created.target.targetRoot, "executed"), "utf8")).toBe(admission.request.cwd);
      await expect(lstat(join(source, "executed"))).rejects.toMatchObject({ code: "ENOENT" });
      expect(JSON.stringify(result)).not.toContain(admission.request.env.HOME);
    } finally {
      expect((await cleanupDisposableTarget(created.target)).status).toBe("passed");
    }
  });

  it("preserves literal argv, the exact environment and async progress through actual close", async () => {
    const args = ["space kept", "$(touch shell-canary)", "; touch other-canary", "line\nbreak"];
    const p = await fixture("process.stdout.write('READY '+Date.now()+'\\n'); setTimeout(()=>{process.stdout.write(JSON.stringify({args:process.argv.slice(2),cwd:process.cwd(),names:Object.keys(process.env)})); process.stderr.write('FINAL\\n');},180);", { ONLY_APPROVED: "set" }, args);
    let observedFirstByte = 0;
    let heartbeats = 0;
    const heartbeat = setInterval(() => { if (observedFirstByte) heartbeats++; }, 10);
    let result: BoundedProcessResult;
    try { result = await run(p.request, { onFirstByte: () => { observedFirstByte = Date.now(); } }); }
    finally { clearInterval(heartbeat); }
    expect(result).toMatchObject({ state: "exited", succeeded: true, exit: { code: 0, signal: null }, close: { code: 0, signal: null }, errors: [], termination: { tree: "absent", attempts: [] } });
    const [firstLine, json] = result.stdout.head.split("\n");
    const observed = JSON.parse(json!);
    // The macOS native runtime may inject this platform variable after exec.
    observed.names = observed.names.filter((name: string) => name !== "__CF_USER_TEXT_ENCODING");
    expect(observed).toEqual({ args, cwd: p.dir, names: ["PATH", "ONLY_APPROVED"] });
    expect(observedFirstByte - Number(firstLine!.split(" ")[1])).toBeLessThan(150);
    expect(heartbeats).toBeGreaterThan(5);
    expect(result.fromFirstByteMs).toBeGreaterThan(140);
    expect(result.stderr.head).toBe("FINAL\n");
    expect(result.stdout.complete).toBe(true); expect(result.stderr.complete).toBe(true);
    expect(Date.parse(result.close!.at)).toBeGreaterThanOrEqual(Date.parse(result.exit!.at));
    await expect(lstat(join(p.dir, "shell-canary"))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(join(p.dir, "other-canary"))).rejects.toMatchObject({ code: "ENOENT" });
    assertNoProcess(result.pid!);
  });

  it("suppresses Node's implicit parent coverage environment without mutating B1's frozen env", async () => {
    const p = await fixture("process.stdout.write(JSON.stringify({coverage:process.env.NODE_V8_COVERAGE??null,parent:process.env.HARVEY_PARENT_SECRET_CANARY??null}));");
    const previousCoverage = process.env.NODE_V8_COVERAGE;
    const previousCanary = process.env.HARVEY_PARENT_SECRET_CANARY;
    process.env.NODE_V8_COVERAGE = join(p.dir, "unapproved-coverage");
    process.env.HARVEY_PARENT_SECRET_CANARY = "MUST_NOT_REACH_CHILD";
    try {
      const result = await run(p.request);
      expect(result.succeeded).toBe(true);
      expect(JSON.parse(result.stdout.head)).toEqual({ coverage: null, parent: null });
      expect(Object.hasOwn(p.request.env, "NODE_V8_COVERAGE")).toBe(false);
      await expect(lstat(join(p.dir, "unapproved-coverage"))).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      if (previousCoverage === undefined) delete process.env.NODE_V8_COVERAGE; else process.env.NODE_V8_COVERAGE = previousCoverage;
      if (previousCanary === undefined) delete process.env.HARVEY_PARENT_SECRET_CANARY; else process.env.HARVEY_PARENT_SECRET_CANARY = previousCanary;
    }
  });

  it.each(["child_process", "stream"])("refuses Node's raw %s debug logger before a child or secret diagnostic can occur", async (debug) => {
    const moduleUrl = new URL("../test-fixtures/readiness-native-process-group.ts", import.meta.url).href;
    const secret = "DEBUG_LOG_MUST_NOT_CONTAIN_THIS_TOKEN";
    const p = await fixture(`(async()=>{
const {createBoundedProcessRunner}=await import(${JSON.stringify(moduleUrl)});
const result=await createBoundedProcessRunner().run({bin:process.execPath,args:['-e',"require('node:fs').writeFileSync('should-not-run','bad')"],cwd:process.cwd(),shell:false,env:{TOKEN:require('node:fs').readFileSync('approved-value','utf8')}},{timeoutMs:1000,redact:text=>text});
process.stdout.write(JSON.stringify(result));
})().catch(()=>{process.stderr.write('fixture import failed');process.exitCode=1;});`, { NODE_DEBUG: debug });
    // Loader startup precedes this module's authority; admit the canary only after import.
    await writeFile(join(p.dir, "approved-value"), secret, { mode: 0o600 });
    const request = { ...p.request, env: p.request.env, args: ["--import", createRequire(import.meta.url).resolve("tsx"), ...p.request.args] };
    const observed = await run(request, { output: { headBytes: 64 * 1024, tailBytes: 64 * 1024 } });
    expect(observed.exit?.code).toBe(0);
    expect(JSON.parse(observed.stdout.head)).toMatchObject({ state: "spawn-error", succeeded: false, pid: null, spawnedAt: null, close: null, errors: [{ phase: "spawn", code: "UNSAFE_PARENT_DIAGNOSTICS" }] });
    expect(JSON.stringify(observed)).not.toContain(secret);
    await expect(lstat(join(p.dir, "should-not-run"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("retains nonzero exit and separate stdout/stderr even when the last stderr bytes arrive late", async () => {
    const p = await fixture("process.stdout.write('out\\n'); process.stderr.write('initial\\n'); setTimeout(()=>{process.stderr.write('FINAL-FAILURE\\n'); process.exitCode=9;},40);");
    const result = await run(p.request);
    expect(result).toMatchObject({ state: "exited", succeeded: false, exit: { code: 9, signal: null }, close: { code: 9, signal: null } });
    expect(result.stdout.head).toBe("out\n");
    expect(result.stderr.head).toBe("initial\nFINAL-FAILURE\n");
    expect(result.stderr.sha256).toBe(digest("initial\nFINAL-FAILURE\n"));
    assertNoProcess(result.pid!);
  });

  it("records missing executable error and real close without serializing its raw error, args or environment", async () => {
    const secret = "ENV_CANARY_NEVER_IN_DIAGNOSTICS";
    const p = await fixture("", { SECRET: secret });
    const request = { bin: join(p.dir, `${secret}-missing`), args: [secret], cwd: p.dir, env: p.request.env, shell: false as const };
    const result = await run(request);
    expect(result).toMatchObject({ state: "spawn-error", succeeded: false, spawnedAt: null, exit: null, close: { signal: null }, errors: [{ phase: "spawn", code: "ENOENT" }], termination: { tree: "not-started" } });
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(JSON.stringify(result)).not.toContain(p.dir);
  });

  it("retains native signal termination and does not turn it into a zero exit", async () => {
    const p = await fixture("process.stdout.write('READY\\n'); process.kill(process.pid,'SIGTERM');");
    const result = await run(p.request);
    expect(result).toMatchObject({ state: "exited", succeeded: false, exit: { code: null, signal: "SIGTERM" }, close: { code: null, signal: "SIGTERM" } });
    assertNoProcess(result.pid!);
  });

  it("drains and hashes entire large streams while keeping bounded nonoverlapping head and final tail", async () => {
    const out = `OUT-BEGIN:${"x".repeat(2 * 1024 * 1024)}:OUT-END`;
    const err = `ERR-BEGIN:${"y".repeat(1024 * 1024)}:FINAL-STDERR-TAIL`;
    const p = await fixture("process.stdout.write('OUT-BEGIN:'+'x'.repeat(2*1024*1024)+':OUT-END'); process.stderr.write('ERR-BEGIN:'+'y'.repeat(1024*1024)); setTimeout(()=>process.stderr.write(':FINAL-STDERR-TAIL'),40);");
    const result = await run(p.request, { output: { headBytes: 32, tailBytes: 64 } });
    expect(result).toMatchObject({ state: "exited", succeeded: false, close: { code: 0 } });
    for (const [stream, raw] of [[result.stdout, out], [result.stderr, err]] as const) {
      expect(stream).toMatchObject({ bytes: Buffer.byteLength(raw), sha256: digest(raw), head: raw.slice(0, 32), tail: raw.slice(-64), headBytes: 32, tailBytes: 64, omittedBytes: Buffer.byteLength(raw) - 96, truncated: true, complete: true, redactionTruncated: false });
      expect(Buffer.byteLength(stream.head)).toBeLessThanOrEqual(32);
      expect(Buffer.byteLength(stream.tail)).toBeLessThanOrEqual(64);
    }
    expect(result.stderr.tail.endsWith(":FINAL-STDERR-TAIL")).toBe(true);
  });

  it.each([7, 8, 9, 16, 17])("accounts for exactly %i raw bytes with no duplicated head/tail bytes", async (length) => {
    const p = await fixture(`process.stdout.write('a'.repeat(${length}));`);
    const result = await run(p.request, { output: { headBytes: 8, tailBytes: 8 } });
    expect(result.stdout.headBytes + result.stdout.tailBytes + result.stdout.omittedBytes).toBe(length);
    expect(result.stdout.head + result.stdout.tail).toBe("a".repeat(Math.min(length, 16)));
    expect(result.stdout.truncated).toBe(length > 16);
    expect(result.succeeded).toBe(length <= 16);
  });

  it("aligns UTF-8 excerpt cuts and still hashes the original byte sequence", async () => {
    const output = `A🐈${"x".repeat(40)}🐈Z`;
    const p = await fixture(`process.stdout.write(${JSON.stringify(output)});`);
    const result = await run(p.request, { output: { headBytes: 3, tailBytes: 3 } });
    expect(result.stdout).toMatchObject({ head: "A", tail: "Z", headBytes: 1, tailBytes: 1, bytes: Buffer.byteLength(output), sha256: digest(output), omittedBytes: Buffer.byteLength(output) - 2, truncated: true, complete: true });
    expect(result.stdout.head + result.stdout.tail).not.toContain("�");
  });

  it("times out a silent real child within the timeout and bounded reap grace", async () => {
    const p = await fixture("setInterval(()=>{},1000);");
    const result = await run(p.request, { timeoutMs: 300 });
    expect(result).toMatchObject({ state: "timed-out", succeeded: false, firstByteAt: null, exit: { signal: "SIGTERM" }, close: { signal: "SIGTERM" }, termination: { reason: "timeout", tree: "absent", stdioForcedClosed: false } });
    expect(result.termination.attempts).toMatchObject([{ signal: "SIGTERM", status: "sent" }]);
    expect(result.durationMs).toBeLessThan(1_500);
    assertNoProcess(result.pid!);
  });

  it("retains graceful timeout-handler stderr and exit 0 as a timed-out failure", async () => {
    const p = await fixture("process.on('SIGTERM',()=>{process.stderr.write('GRACEFUL-TAIL\\n',()=>process.exit(0));}); process.stdout.write('READY\\n'); setInterval(()=>{},1000);");
    const result = await run(p.request, { timeoutMs: 400, killGraceMs: 250 });
    expect(result).toMatchObject({ state: "timed-out", succeeded: false, exit: { code: 0, signal: null }, close: { code: 0, signal: null }, stderr: { head: "GRACEFUL-TAIL\n", complete: true } });
    expect(result.firstByteAt).not.toBeNull();
    expect(result.termination.attempts.map((attempt) => attempt.signal)).toEqual(["SIGTERM"]);
    assertNoProcess(result.pid!);
  });

  it("escalates a SIGTERM-resistant child to SIGKILL and retains both signal attempts", async () => {
    const p = await fixture("process.on('SIGTERM',()=>process.stderr.write('IGNORED-TERM\\n')); process.stdout.write('READY\\n'); setInterval(()=>{},1000);");
    const result = await run(p.request, { timeoutMs: 400 });
    expect(result).toMatchObject({ state: "timed-out", succeeded: false, exit: { code: null, signal: "SIGKILL" }, close: { code: null, signal: "SIGKILL" }, stderr: { head: "IGNORED-TERM\n" }, termination: { reason: "timeout", tree: "absent" } });
    expect(result.termination.attempts.map((attempt) => [attempt.signal, attempt.status])).toEqual([["SIGTERM", "sent"], ["SIGKILL", "sent"]]);
    assertNoProcess(result.pid!);
  });

  it("does not resolve a zero-exit wrapper before a descendant-held stderr closes", async () => {
    const p = await fixture(`const {spawn}=require('node:child_process');
const child=spawn(process.execPath,['-e',"console.log('DESCENDANT-READY'); setTimeout(()=>console.error('AFTER-WRAPPER-EXIT'),180);"],{stdio:['ignore','inherit','inherit']});
process.stdout.write('WRAPPER-READY\\n'); child.unref(); process.exit(0);`);
    const result = await run(p.request);
    expect(result.exit).toMatchObject({ code: 0, signal: null });
    expect(result.close).toMatchObject({ code: 0, signal: null });
    expect(result.stderr.head).toBe("AFTER-WRAPPER-EXIT\n");
    expect(result.stderr.complete).toBe(true);
    expect(Date.parse(result.close!.at) - Date.parse(result.exit!.at)).toBeGreaterThan(100);
  });

  it("kills a descendant that holds fds after the wrapper has already exited zero", async () => {
    const p = await fixture(`const {spawn}=require('node:child_process');
const child=spawn(process.execPath,['-e',"require('node:fs').writeFileSync('descendant.pid',String(process.pid)); process.on('SIGTERM',()=>console.error('DESCENDANT-TERM')); console.log('DESCENDANT-READY'); setInterval(()=>{},1000);"],{stdio:['ignore','inherit','inherit']});
child.unref(); process.exit(0);`);
    const result = await run(p.request, { timeoutMs: 400 });
    expect(result.succeeded).toBe(false);
    expect(result.exit).toMatchObject({ code: 0, signal: null });
    expect(result.close).toMatchObject({ code: 0, signal: null });
    expect(result.termination.reason).toBe("timeout");
    expect(result.termination.attempts.map((attempt) => [attempt.signal, attempt.status])).toEqual([["SIGTERM", "sent"], ["SIGKILL", "sent"]]);
    expect(result.stderr.head).toBe("DESCENDANT-TERM\n");
    expect(result.stderr.complete).toBe(true);
    assertNoProcess(Number(await readFile(join(p.dir, "descendant.pid"), "utf8")));
  });

  it("terminates background descendants even when they have closed all inherited output fds", async () => {
    const p = await fixture(`const {spawn}=require('node:child_process'); const fs=require('node:fs');
const child=spawn(process.execPath,['-e',"require('node:fs').writeFileSync('descendant.pid',String(process.pid)); setInterval(()=>{},1000);"],{stdio:'ignore'});
const wait=setInterval(()=>{if(fs.existsSync('descendant.pid')){clearInterval(wait);child.unref();process.exit(0);}},10);`);
    const result = await run(p.request);
    expect(result).toMatchObject({ state: "descendant-cleanup", succeeded: false, exit: { code: 0 }, close: { code: 0 }, termination: { reason: "descendants", tree: "absent" } });
    expect(result.termination.attempts[0]).toMatchObject({ signal: "SIGTERM", status: "sent" });
    assertNoProcess(Number(await readFile(join(p.dir, "descendant.pid"), "utf8")));
  });

  it("bounds an escaped fd holder without fabricating close or complete stream evidence", async () => {
    const p = await fixture(`const {spawn}=require('node:child_process');
const child=spawn(process.execPath,['-e',"require('node:fs').writeFileSync('escaped.pid',String(process.pid)); console.log('ESCAPED-READY'); setInterval(()=>{},1000);"],{detached:true,stdio:['ignore','inherit','inherit']});
child.unref(); process.exit(0);`);
    const result = await run(p.request, { timeoutMs: 300, closeGraceMs: 150 });
    expect(result).toMatchObject({ state: "termination-unconfirmed", succeeded: false, exit: { code: 0 }, close: null, termination: { reason: "timeout", stdioForcedClosed: true }, stdout: { complete: false }, stderr: { complete: false } });
    expect(result.errors).toContainEqual({ phase: "termination", code: "TERMINATION_UNCONFIRMED" });
    expect(result.durationMs).toBeLessThan(1_500);
    pids.add(Number(await readFile(join(p.dir, "escaped.pid"), "utf8")));
  });

  it("discloses that original-group absence cannot establish detached descendant ownership", async () => {
    const p = await fixture(`const {spawn}=require('node:child_process');const fs=require('node:fs');
const child=spawn(process.execPath,['-e',"require('node:fs').writeFileSync('escaped.pid',String(process.pid));setInterval(()=>require('node:fs').appendFileSync('heartbeat','tick'),20);"],{detached:true,stdio:'ignore'});
child.unref();const wait=setInterval(()=>{if(fs.existsSync('heartbeat')){clearInterval(wait);process.exit(0);}},10);`);
    const result = await run(p.request);
    const escaped = Number(await readFile(join(p.dir, "escaped.pid"), "utf8")); pids.add(escaped);
    // Native helper success retains unproven descendant ownership for the readiness decision.
    expect(result).toMatchObject({ state: "exited", succeeded: true, termination: { tree: "absent" }, containment: { kind: "native-process-group", descendantOwnership: "unproven", groupObservation: "absent" } });
    expect(() => process.kill(escaped, 0)).not.toThrow();
    const before = await readFile(join(p.dir, "heartbeat"), "utf8");
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect((await readFile(join(p.dir, "heartbeat"), "utf8")).length).toBeGreaterThan(before.length);
  });
});

describe.skipIf(process.platform === "win32")("redactor handoff and concurrency", () => {
  it("gives the redactor full retained text after split writes, without retaining env or raw diagnostics", async () => {
    const secret = "SECRET_SPLIT_ACROSS_CHILD_WRITES";
    const p = await fixture("const s=process.env.TOKEN; process.stdout.write(s.slice(0,8)); setTimeout(()=>{process.stdout.write(s.slice(8)); process.stderr.write(s);},30);", { TOKEN: secret });
    const result = await run(p.request, { redact: (text) => text.replaceAll(secret, "[redacted]") });
    expect(result).toMatchObject({ succeeded: true, stdout: { head: "[redacted]", bytes: secret.length, sha256: digest(secret) }, stderr: { head: "[redacted]" } });
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(Object.keys(result)).not.toContain("env");
  });

  it("supplies transient overlap and cut direction for secret fragments at both excerpt edges", async () => {
    const secret = "BOUNDARY_SECRET_WITH_A_LONG_VALUE";
    const p = await fixture("const s=process.env.TOKEN; process.stdout.write(s+'X'.repeat(80)+s);", { TOKEN: secret });
    const calls: { text: string; context: Parameters<BoundedProcessRedactor>[1] }[] = [];
    const result = await run(p.request, { output: { headBytes: 16, tailBytes: 16 }, redact: (text, context) => { calls.push({ text, context }); return "[redacted]"; } });
    expect(calls.map((call) => call.context.boundary)).toEqual(["head", "tail"]);
    for (const call of calls) expect(call.context.before + call.text + call.context.after).toContain(secret);
    expect(result.stdout).toMatchObject({ head: "[redacted]", tail: "[redacted]", truncated: true });
    expect(JSON.stringify(result)).not.toContain(secret.slice(0, 16));
    expect(JSON.stringify(result)).not.toContain(secret.slice(-16));
    expect(JSON.stringify(result)).not.toContain("before");
    expect(JSON.stringify(result)).not.toContain("after");
  });

  it("labels adjacent head/tail cuts even when the source stream fits the combined bound", async () => {
    const p = await fixture("process.stdout.write('abcdefghijkl');");
    const boundaries: string[] = [];
    const result = await run(p.request, { output: { headBytes: 8, tailBytes: 8 }, redact: (text, context) => { boundaries.push(context.boundary); return text; } });
    expect(result.succeeded).toBe(true);
    expect(boundaries).toEqual(["head", "tail"]);
  });

  it("fails closed on redaction errors and marks safe redaction expansion truncation as non-clean", async () => {
    const secret = "RAW_REDACTION_ERROR_CANARY";
    const p = await fixture("process.stdout.write(process.env.TOKEN);", { TOKEN: secret });
    const broken = await run(p.request, { redact: () => { throw new Error(secret); } });
    expect(broken).toMatchObject({ state: "redaction-error", succeeded: false, stdout: { head: "" }, errors: [{ phase: "redaction", code: "REDACTION_FAILED" }] });
    expect(JSON.stringify(broken)).not.toContain(secret);
    const expanded = await run(p.request, { output: { headBytes: 32, tailBytes: 8 }, redact: () => "[redacted]".repeat(100) });
    expect(expanded).toMatchObject({ succeeded: false, stdout: { truncated: false, redactionTruncated: true } });
    expect(Buffer.byteLength(expanded.stdout.head)).toBeLessThanOrEqual(32);
  });

  it("normalizes throwing observers without leaking the thrown message", async () => {
    const p = await fixture("process.stdout.write('READY\\n'); setInterval(()=>{},1000);");
    const result = await run(p.request, { onFirstByte: () => { throw new Error("OBSERVER_SECRET_CANARY"); } });
    expect(result).toMatchObject({ state: "observer-error", succeeded: false, termination: { reason: "observer-error", tree: "absent" }, errors: [{ phase: "observer", code: "OBSERVER_FAILED" }] });
    expect(JSON.stringify(result)).not.toContain("OBSERVER_SECRET_CANARY");
  });

  it.each([1, 2])("enforces concurrency %i while allowing every queued real child to finish", async (concurrency) => {
    const p = await fixture("process.stdout.write('READY\\n'); setTimeout(()=>process.stderr.write('DONE\\n'),180);");
    const runner = createBoundedProcessRunner({ concurrency });
    let active = 0; let peak = 0;
    const results = await Promise.all(Array.from({ length: 3 }, () => runner.run(p.request, { ...defaults, onFirstByte: () => { active++; peak = Math.max(peak, active); } }).then((result) => { active--; if (result.pid !== null) pids.add(result.pid); return result; })));
    expect(peak).toBe(concurrency);
    expect(results.every((result) => result.succeeded)).toBe(true);
    expect(results[2]!.queueDurationMs).toBeGreaterThan(100);
    expect(active).toBe(0);
  });

  it("settles cancellation before spawn, while queued, and after first byte without leaking a slot", async () => {
    const holder = await fixture("process.stdout.write('READY\\n'); setInterval(()=>{},1000);");
    const canary = await fixture("require('node:fs').writeFileSync('should-not-run','bad');");
    const runner = createBoundedProcessRunner();
    const preAborted = new AbortController(); preAborted.abort();
    const before = await runner.run(canary.request, { ...defaults, signal: preAborted.signal });
    expect(before).toMatchObject({ state: "aborted", succeeded: false, pid: null, spawnedAt: null, close: null });
    let ready!: () => void;
    const started = new Promise<void>((resolve) => { ready = resolve; });
    const currentAbort = new AbortController();
    const current = runner.run(holder.request, { ...defaults, signal: currentAbort.signal, onFirstByte: ready });
    await started;
    const queueAbort = new AbortController();
    const queued = runner.run(canary.request, { ...defaults, signal: queueAbort.signal });
    queueAbort.abort();
    const cancelled = await queued;
    expect(cancelled).toMatchObject({ state: "aborted", pid: null, close: null });
    currentAbort.abort();
    const aborted = await current;
    if (aborted.pid !== null) pids.add(aborted.pid);
    expect(aborted).toMatchObject({ state: "aborted", succeeded: false, close: { signal: "SIGTERM" }, termination: { tree: "absent" } });
    await expect(lstat(join(canary.dir, "should-not-run"))).rejects.toMatchObject({ code: "ENOENT" });
    const healthy = await fixture("process.stdout.write('still-running');");
    expect((await runner.run(healthy.request, defaults)).succeeded).toBe(true);
  });

  it("rejects unsafe invocation/configuration before any child can create its canary", async () => {
    const p = await fixture("require('node:fs').writeFileSync('should-not-run','bad');");
    const runner = createBoundedProcessRunner();
    for (const options of [{ timeoutMs: 0 }, { timeoutMs: Infinity }, { killGraceMs: 60_001 }, { closeGraceMs: -1 }, { output: { headBytes: 0, tailBytes: 16 } }, { redact: undefined }]) {
      await expect(runner.run(p.request, { ...defaults, ...options } as BoundedProcessOptions)).rejects.toThrow(/Bounded process/);
    }
    const unsafe = { ...p.request, env: p.request.env, shell: true } as unknown as ReadinessSpawnRequest;
    await expect(runner.run(unsafe, defaults)).rejects.toThrow(/shell:false/);
    expect(() => createBoundedProcessRunner({ concurrency: 0 })).toThrow(/concurrency/);
    await expect(lstat(join(p.dir, "should-not-run"))).rejects.toMatchObject({ code: "ENOENT" });
  });
});
