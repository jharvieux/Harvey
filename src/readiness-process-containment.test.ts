import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { createServer, request as httpRequest } from "node:http";
import type { Socket } from "node:net";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReadinessSpawnRequest } from "./audit-readiness-authority.js";
import { createReadinessContainedProcessRunner, type ReadinessContainmentConfig } from "./readiness-process-containment.js";
import { cleanupDisposableTarget, createDisposableTarget, type DisposableTarget } from "./disposable-target.js";

const roots: string[] = [];
const targets: DisposableTarget[] = [];
const proxyCleanups: (() => Promise<void>)[] = [];
const config: ReadinessContainmentConfig | undefined = process.env.HARVEY_READINESS_DOCKER_SOCKET && process.env.HARVEY_READINESS_DOCKER_IMAGE ? {
  kind: "docker-local", socketPath: process.env.HARVEY_READINESS_DOCKER_SOCKET, imageId: process.env.HARVEY_READINESS_DOCKER_IMAGE,
} : undefined;
const bounds = { timeoutMs: 3_000, killGraceMs: 150, closeGraceMs: 400, redact: (text: string) => text };

afterEach(async () => {
  for (const close of proxyCleanups.splice(0)) await close();
  for (const target of targets.splice(0)) await cleanupDisposableTarget(target);
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

async function fixture(script: string, env: Record<string, string> = {}, args: string[] = [], parentOverride?: string) {
  const parent = await realpath(parentOverride ?? process.env.HARVEY_READINESS_SHARED_PARENT ?? tmpdir());
  const root = await realpath(await mkdtemp(join(parent, "harvey-contained-test-"))); roots.push(root);
  const source = join(root, "source"), scratch = join(root, "scratch");
  await mkdir(source); await mkdir(scratch);
  await writeFile(join(source, "child.cjs"), script);
  await writeFile(join(source, "package.json"), JSON.stringify({ name: "contained-test", version: "1.0.0", scripts: { test: "node child.cjs" } }));
  const created = await createDisposableTarget(source, { tempParent: scratch });
  if (created.status !== "ready") throw new Error(`Fixture unavailable: ${created.reasonCode}`);
  const target = created.target; targets.push(target);
  const request: ReadinessSpawnRequest = Object.freeze({ bin: "node", args: Object.freeze(["child.cjs", ...args]), cwd: target.targetRoot, shell: false, env: Object.freeze({ PATH: "/usr/local/bin:/usr/bin:/bin", HOME: join(target.root, "home"), TMPDIR: join(target.root, "tmp"), ...env }) });
  const runner = createReadinessContainedProcessRunner({ config, target, approvedEnvNames: Object.keys(env), assertArgv: () => undefined });
  return { target, request, runner, source };
}

async function runtimeProxy(parent: string, fail: "inspect-after-start" | "remove" | "none") {
  const owned = new Set<string>(), observedControls: string[] = [];
  const sockets = new Set<Socket>();
  let started = false;
  const server = createServer((req, res) => {
    if ((fail === "inspect-after-start" && started && req.method === "GET" && /\/containers\/.*\/json$/.test(req.url ?? "")) || (fail === "remove" && req.method === "DELETE")) { res.writeHead(503); res.end("fixture runtime failure"); return; }
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.once("end", () => {
      const raw = Buffer.concat(chunks);
      if (req.url?.includes("/containers/create")) observedControls.push(raw.toString("utf8"));
      if (req.url?.endsWith("/start")) started = true;
      const upstream = httpRequest({ socketPath: config!.socketPath, path: req.url, method: req.method, headers: req.headers }, (response) => {
        res.writeHead(response.statusCode ?? 502, response.headers);
        const body: Buffer[] = [];
        response.on("data", (chunk: Buffer) => { if (req.url?.includes("/containers/create")) body.push(chunk); });
        response.once("end", () => { if (body.length && response.statusCode === 201) { const created = JSON.parse(Buffer.concat(body).toString("utf8")); if (/^[a-f0-9]{64}$/.test(created.Id)) owned.add(created.Id); } });
        response.pipe(res);
      });
      upstream.once("error", () => { res.writeHead(502); res.end(); });
      upstream.end(raw);
    });
  });
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  server.on("upgrade", (req, downstream, head) => {
    const upstream = httpRequest({ socketPath: config!.socketPath, path: req.url, method: req.method, headers: req.headers });
    upstream.once("upgrade", (response, socket, upstreamHead) => {
      sockets.add(socket); socket.once("close", () => sockets.delete(socket));
      downstream.write(`HTTP/1.1 ${response.statusCode} Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n`);
      if (upstreamHead.length) downstream.write(upstreamHead);
      if (head.length) socket.write(head);
      downstream.pipe(socket); socket.pipe(downstream);
      downstream.on("error", () => socket.destroy()); socket.on("error", () => downstream.destroy());
    });
    upstream.once("error", () => downstream.destroy()); upstream.end();
  });
  const socketPath = join(parent, "runtime-proxy.sock");
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(socketPath, resolve); });
  await chmod(socketPath, 0o600);
  proxyCleanups.push(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    // These IDs came only from this proxy's successful create responses.
    for (const id of owned) await new Promise<void>((resolve, reject) => {
      const req = httpRequest({ socketPath: config!.socketPath, method: "DELETE", path: `/v1.44/containers/${id}?force=true&v=false`, timeout: 5_000 }, (res) => { res.resume(); res.once("end", () => res.statusCode === 204 || res.statusCode === 404 ? resolve() : reject(new Error("Owned fixture cleanup failed"))); });
      req.once("timeout", () => req.destroy(new Error("Owned fixture cleanup timed out"))); req.once("error", reject); req.end();
    });
  });
  return { socketPath, owned, observedControls };
}

describe("readiness containment prerequisites", () => {
  it("has no native execution fallback when containment is not configured", async () => {
    const p = await fixture("require('node:fs').writeFileSync('executed','bad');");
    const runner = createReadinessContainedProcessRunner({ target: p.target, approvedEnvNames: [], assertArgv: () => undefined });
    expect(await runner.probe()).toMatchObject({ status: "unavailable", reasonCode: "containment-not-configured" });
    const result = await runner.run(p.request, bounds);
    expect(result).toMatchObject({ state: "containment-unavailable", succeeded: false, pid: null, spawnedAt: null, exit: null, close: null, containment: { kind: "unavailable", reasonCode: "containment-not-configured" } });
    await expect(lstat(join(p.target.targetRoot, "executed"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects mutable images and remote runtime endpoints", async () => {
    const p = await fixture("");
    for (const value of [{ kind: "docker-local", socketPath: "/missing.sock", imageId: "node:latest" }, { kind: "docker-local", socketPath: "tcp://localhost:2375", imageId: `sha256:${"a".repeat(64)}` }]) {
      expect(() => createReadinessContainedProcessRunner({ config: value as ReadinessContainmentConfig, target: p.target, approvedEnvNames: [], assertArgv: () => undefined })).toThrow(/trusted local Unix socket/);
    }
  });

  it.each(["stream", "http", "net"])("refuses parent %s diagnostics before runtime transport can expose raw values", async (channel) => {
    const secret = "PRIVATE_INPUT_DEBUG_CANARY";
    const module = new URL("./readiness-process-containment.ts", import.meta.url).href;
    const code = `const {createReadinessContainedProcessRunner}=await import(${JSON.stringify(module)});const runner=createReadinessContainedProcessRunner({config:{kind:'docker-local',socketPath:'/not-contacted.sock',imageId:'sha256:'+'a'.repeat(64)},target:{},approvedEnvNames:['APPROVED'],assertArgv:()=>{throw Error('guard should not be reached');}});const result=await runner.run({bin:'node',args:['-e','process.exit(0)'],cwd:process.cwd(),shell:false,env:{PATH:'/usr/local/bin:/usr/bin:/bin',APPROVED:process.env.DEBUG_CANARY}},{timeoutMs:500,redact:()=>''});process.stdout.write(JSON.stringify(result));`;
    const output = await promisify(execFile)(process.execPath, ["--import", createRequire(import.meta.url).resolve("tsx"), "--input-type=module", "-e", code], {
      env: { PATH: process.env.PATH, NODE_DEBUG: channel, DEBUG_CANARY: secret, NODE_V8_COVERAGE: undefined }, timeout: 5_000, maxBuffer: 1024 * 1024,
    });
    expect(JSON.parse(output.stdout)).toMatchObject({ state: "containment-unavailable", pid: null, containment: { kind: "unavailable", reasonCode: "containment-parent-diagnostics-unsafe" } });
    expect(output.stdout + output.stderr).not.toContain(secret);
  });
});

describe.skipIf(!config)("physical local PID namespace adapter", () => {
  it("withholds a root target group before creating any runtime lease", async () => {
    const p = await fixture("require('node:fs').writeFileSync('ran','yes');");
    const gid = vi.spyOn(process as NodeJS.Process & { getgid: () => number }, "getgid").mockReturnValue(0);
    try {
      const result = await p.runner.run(p.request, bounds);
      expect(result).toMatchObject({ succeeded: false, pid: null, spawnedAt: null, containment: { kind: "unavailable", reasonCode: "containment-target-identity-unavailable" } });
      await expect(lstat(join(p.target.targetRoot, "ran"))).rejects.toMatchObject({ code: "ENOENT" });
    } finally { gid.mockRestore(); }
  });

  it("preserves actual target lifecycle, exact environment and separate last stderr", async () => {
    const p = await fixture("process.stdout.write(JSON.stringify({cwd:process.cwd(),env:process.env,args:process.argv.slice(2)}));setTimeout(()=>process.stderr.write('LAST-STDERR'),40);", { APPROVED: "env-only-canary" }, ["space kept", "$(false)"]);
    expect(await p.runner.probe()).toMatchObject({ status: "ready", imageId: config!.imageId });
    const result = await p.runner.run(p.request, bounds);
    expect(result, JSON.stringify(result)).toMatchObject({ state: "exited", succeeded: true, exit: { code: 0, signal: null }, close: { code: 0, signal: null }, errors: [], stderr: { head: "LAST-STDERR", complete: true }, containment: { kind: "docker-pid-namespace", namespace: "terminated", targetWork: "begun", metadata: "verified", cleanup: "removed", targetIdentity: { uid: process.getuid!(), gid: process.getgid!(), capEff: "0000000000000000", noNewPrivileges: true } } });
    expect(JSON.parse(result.stdout.head)).toEqual({ cwd: p.request.cwd, env: p.request.env, args: ["space kept", "$(false)"] });
    expect(result.pid).toBeGreaterThan(1);
  });

  it("runs a selected npm script with a real zero exit", async () => {
    const p = await fixture("process.stdout.write('NPM-SCRIPT-RAN');");
    const result = await p.runner.run({ ...p.request, bin: "npm", args: ["run", "test"] }, bounds);
    expect(result, JSON.stringify(result)).toMatchObject({ succeeded: true, state: "exited", exit: { code: 0, signal: null }, containment: { namespace: "terminated", metadata: "verified", cleanup: "removed" } });
    expect(result.stdout.head).toContain("NPM-SCRIPT-RAN");
  });

  it.each([{ script: "process.exitCode=7", code: 7, signal: null }, { script: "process.kill(process.pid,'SIGTERM')", code: null, signal: "SIGTERM" }, { script: "process.exitCode=137", code: 137, signal: null }])("retains actual code $code and signal $signal", async ({ script, code, signal }) => {
    const p = await fixture(script);
    const result = await p.runner.run(p.request, bounds);
    expect(result, JSON.stringify(result)).toMatchObject({ state: "exited", succeeded: false, exit: { code, signal }, close: { code, signal }, containment: { namespace: "terminated", metadata: "verified", cleanup: "removed" } });
  });

  it("reports a missing executable without inventing a target exit", async () => {
    const p = await fixture("");
    const result = await p.runner.run({ ...p.request, bin: "harvey-executable-that-does-not-exist" }, bounds);
    expect(result, JSON.stringify(result)).toMatchObject({ state: "spawn-error", succeeded: false, pid: null, spawnedAt: null, exit: null, close: { signal: null }, errors: [{ phase: "spawn", code: "ENOENT" }], containment: { namespace: "terminated", targetWork: "not-started", metadata: "verified", cleanup: "removed" } });
  });

  it("hashes full raw streams while bounding head and final stderr tail", async () => {
    const raw = `BEGIN${"x".repeat(200_000)}END`, err = `START${"y".repeat(100_000)}FINAL-TAIL`;
    const p = await fixture("process.stdout.write('BEGIN'+'x'.repeat(200000)+'END');process.stderr.write('START'+'y'.repeat(100000));setTimeout(()=>process.stderr.write('FINAL-TAIL'),30);");
    const result = await p.runner.run(p.request, { ...bounds, output: { headBytes: 16, tailBytes: 32 } });
    expect(result, JSON.stringify(result)).toMatchObject({ state: "exited", succeeded: false, containment: { namespace: "terminated", metadata: "verified", cleanup: "removed" } });
    for (const [stream, text] of [[result.stdout, raw], [result.stderr, err]] as const) expect(stream).toMatchObject({ bytes: Buffer.byteLength(text), sha256: createHash("sha256").update(text).digest("hex"), head: text.slice(0, 16), tail: text.slice(-32), complete: true, truncated: true });
  });

  it("kills detached stdio-ignore descendants when the namespace init exits", async () => {
    const p = await fixture("const cp=require('node:child_process'),fs=require('node:fs');const c=cp.spawn(process.execPath,['-e',\"setInterval(()=>require('node:fs').appendFileSync('heartbeat','tick\\\\n'),20)\"],{detached:true,stdio:'ignore'});c.unref();setTimeout(()=>process.exit(0),150);");
    const result = await p.runner.run(p.request, bounds);
    expect(result, JSON.stringify(result)).toMatchObject({ succeeded: true, containment: { namespace: "terminated", terminalObservation: { running: false, pid: 0 }, cleanup: "removed" } });
    const before = await readFile(join(p.target.targetRoot, "heartbeat"), "utf8");
    expect(before.length).toBeGreaterThan(0);
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(await readFile(join(p.target.targetRoot, "heartbeat"), "utf8")).toBe(before);
  });

  it("terminates inherited-pipe escapees without fabricating target close or full streams", async () => {
    const p = await fixture("const c=require('node:child_process').spawn(process.execPath,['-e',\"setInterval(()=>require('node:fs').appendFileSync('heartbeat','tick\\\\n'),20)\"],{detached:true,stdio:['ignore','inherit','inherit']});c.unref();setTimeout(()=>process.exit(0),150);");
    const result = await p.runner.run(p.request, bounds);
    expect(result, JSON.stringify(result)).toMatchObject({ state: "descendant-cleanup", succeeded: false, exit: { code: 0 }, close: null, termination: { stdioForcedClosed: true, tree: "absent" }, stdout: { complete: false }, stderr: { complete: false }, containment: { namespace: "terminated", cleanup: "removed" } });
    const before = await readFile(join(p.target.targetRoot, "heartbeat"), "utf8");
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(await readFile(join(p.target.targetRoot, "heartbeat"), "utf8")).toBe(before);
  });

  it.each([{ resistant: false, signal: "SIGTERM" }, { resistant: true, signal: "SIGKILL" }])("bounds target timeout with actual $signal observation", async ({ resistant, signal }) => {
    const p = await fixture(`${resistant ? "process.on('SIGTERM',()=>process.stderr.write('TERM-IGNORED'));" : ""}process.stdout.write('READY');setInterval(()=>{},1000);`);
    const result = await p.runner.run(p.request, { ...bounds, timeoutMs: 300 });
    expect(result, JSON.stringify(result)).toMatchObject({ state: "timed-out", succeeded: false, exit: { code: null, signal }, close: { code: null, signal }, termination: { reason: "timeout", tree: "absent" }, containment: { namespace: "terminated", metadata: "verified", cleanup: "removed" } });
    expect(result.termination.attempts.map((row) => row.signal)).toEqual(resistant ? ["SIGTERM", "SIGKILL"] : ["SIGTERM"]);
    expect(result.durationMs).toBeLessThan(3_000);
  });

  it("preserves timeout as failure when the target exits zero from its signal handler", async () => {
    const p = await fixture("process.on('SIGTERM',()=>process.stderr.write('GRACEFUL-TAIL',()=>process.exit(0)));process.stdout.write('READY');setInterval(()=>{},1000);");
    const result = await p.runner.run(p.request, { ...bounds, timeoutMs: 300 });
    expect(result, JSON.stringify(result)).toMatchObject({ state: "timed-out", succeeded: false, exit: { code: 0, signal: null }, close: { code: 0, signal: null }, stderr: { head: "GRACEFUL-TAIL", complete: true }, containment: { namespace: "terminated", cleanup: "removed" } });
  });

  it("records abort after first byte and a failing output observer", async () => {
    const p = await fixture("process.stdout.write('READY');setInterval(()=>{},1000);");
    const controller = new AbortController();
    const aborted = await p.runner.run(p.request, { ...bounds, signal: controller.signal, onFirstByte: () => controller.abort() });
    expect(aborted, JSON.stringify(aborted)).toMatchObject({ state: "aborted", succeeded: false, exit: { signal: "SIGTERM" }, containment: { namespace: "terminated", cleanup: "removed" } });
    const broken = await p.runner.run(p.request, { ...bounds, onFirstByte: () => { throw new Error("OBSERVATION_SECRET_DO_NOT_LOG"); } });
    expect(broken, JSON.stringify(broken)).toMatchObject({ state: "observer-error", succeeded: false, containment: { namespace: "terminated", cleanup: "removed" } });
    expect(JSON.stringify(broken)).not.toContain("OBSERVATION_SECRET_DO_NOT_LOG");
  });

  it("redacts approved public values and refuses them in target argv before work", async () => {
    const secret = "PUBLIC_APPROVED_CANARY";
    const p = await fixture("require('node:fs').writeFileSync('ran','yes');process.stdout.write(process.env.APPROVED);process.stderr.write(process.env.APPROVED);", { APPROVED: secret });
    const unsafe = await p.runner.run({ ...p.request, args: ["child.cjs", secret] }, bounds);
    expect(unsafe, JSON.stringify(unsafe)).toMatchObject({ state: "containment-unavailable", pid: null, containment: { targetWork: "not-started", namespace: "not-started", cleanup: "not-required" }, errors: [{ phase: "spawn", code: "UNSAFE_ARGV" }] });
    await expect(lstat(join(p.target.targetRoot, "ran"))).rejects.toMatchObject({ code: "ENOENT" });
    const result = await p.runner.run(p.request, { ...bounds, redact: (text) => text.replaceAll(secret, "[redacted]") });
    expect(result).toMatchObject({ succeeded: true, stdout: { head: "[redacted]", bytes: secret.length, sha256: createHash("sha256").update(secret).digest("hex") }, stderr: { head: "[redacted]" } });
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(JSON.stringify(unsafe)).not.toContain(secret);
  });

  it("keeps original source, root metadata and the observer outside target write authority", async () => {
    const p = await fixture("");
    const script = `const fs=require('node:fs'),cp=require('node:child_process');
const results={};for(const [name,fn] of Object.entries({source:()=>fs.writeFileSync(${JSON.stringify(join(p.source, "host-canary"))},'changed'),root:()=>fs.writeFileSync('/root/harvey-test','bad'),observer:()=>process.kill(1,'SIGKILL'),metadata:()=>{const dir=fs.readdirSync('/').find(n=>n.startsWith('.harvey-readiness-'));fs.writeFileSync('/'+dir+'/result.json',JSON.stringify({exit:{code:0}}));}})){try{fn();results[name]='unexpected-success';}catch(e){results[name]=e.code;}}
results.parent=fs.readFileSync('/proc/self/status','utf8').match(/^(CapEff|NoNewPrivs):.*$/gm);results.child=cp.execFileSync(process.execPath,['-e',"process.stdout.write(require('node:fs').readFileSync('/proc/self/status','utf8').match(/^(CapEff|NoNewPrivs):.*$/gm).join('|'))"],{encoding:'utf8'});fs.writeFileSync('attempts.json',JSON.stringify(results));process.stdout.write('FORGED_TARGET_SUCCESS: '+JSON.stringify({exit:{code:0},containerId:'fake'}));process.exitCode=9;`;
    await writeFile(join(p.target.targetRoot, "child.cjs"), script);
    const result = await p.runner.run(p.request, bounds);
    const attempts = JSON.parse(await readFile(join(p.target.targetRoot, "attempts.json"), "utf8"));
    expect(attempts).toMatchObject({ source: "ENOENT", root: "EACCES", observer: "EPERM", metadata: "EACCES" });
    expect(result, JSON.stringify(result)).toMatchObject({ state: "exited", succeeded: false, exit: { code: 9 }, close: { code: 9 }, containment: { metadata: "verified", cleanup: "removed" } });
    expect(attempts.parent).toEqual(["CapEff:\t0000000000000000", "NoNewPrivs:\t1"]);
    expect(attempts.child).toBe("CapEff:\t0000000000000000|NoNewPrivs:\t1");
    await expect(lstat(join(p.source, "host-canary"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("reports absent local image or socket as zero target work", async () => {
    const p = await fixture("require('node:fs').writeFileSync('ran','bad');");
    for (const override of [{ imageId: `sha256:${"a".repeat(64)}` }, { socketPath: join(p.source, "missing.sock") }]) {
      const runner = createReadinessContainedProcessRunner({ config: { ...config!, ...override }, target: p.target, approvedEnvNames: [], assertArgv: () => undefined });
      const result = await runner.run(p.request, bounds);
      expect(result).toMatchObject({ state: "containment-unavailable", pid: null, containment: { kind: "unavailable" } });
      await expect(lstat(join(p.target.targetRoot, "ran"))).rejects.toMatchObject({ code: "ENOENT" });
    }
  });

  it("refuses target-writable image PATH entries before target spawn", async () => {
    const p = await fixture("require('node:fs').writeFileSync('ran','bad');");
    const toolchainPath = "/tmp:/usr/local/bin:/usr/bin:/bin";
    const runner = createReadinessContainedProcessRunner({ config: { ...config!, toolchainPath }, target: p.target, approvedEnvNames: [], assertArgv: () => undefined });
    const result = await runner.run({ ...p.request, env: { ...p.request.env, PATH: toolchainPath } }, bounds);
    expect(result, JSON.stringify(result)).toMatchObject({ state: "containment-unavailable", pid: null, spawnedAt: null, exit: null, errors: [{ phase: "observer", code: "IMAGE_TOOLCHAIN_UNTRUSTED" }], containment: { namespace: "terminated", targetWork: "not-started", cleanup: "removed", metadata: "verified" } });
    await expect(lstat(join(p.target.targetRoot, "ran"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.skipIf(process.platform !== "darwin" || !config?.socketPath.includes("/.colima/"))("does not substitute a different copy when the VM cannot mount the real disposable root", async () => {
    const p = await fixture("require('node:fs').writeFileSync('ran','bad');", {}, [], tmpdir());
    const result = await p.runner.run(p.request, bounds);
    expect(result, JSON.stringify(result)).toMatchObject({ state: "containment-unavailable", pid: null, spawnedAt: null, containment: { targetWork: "not-started", namespace: "not-started", cleanup: "not-required" } });
    await expect(lstat(join(p.target.targetRoot, "ran"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each(["inspect-after-start", "remove"] as const)("retains exact ownership and poisons reuse after runtime %s failure", async (failure) => {
    const p = await fixture("process.stdout.write('actual target');");
    const proxy = await runtimeProxy(dirname(p.source), failure);
    const runner = createReadinessContainedProcessRunner({ config: { ...config!, socketPath: proxy.socketPath }, target: p.target, approvedEnvNames: [], assertArgv: () => undefined });
    const result = await runner.run(p.request, bounds);
    expect(result, JSON.stringify(result)).toMatchObject({ succeeded: false, containment: { kind: "docker-pid-namespace", namespace: failure === "remove" ? "terminated" : "unconfirmed", cleanup: "retained" } });
    if (result.containment.kind !== "docker-pid-namespace") throw new Error("Expected owned container evidence");
    expect(proxy.owned.has(result.containment.containerId!)).toBe(true);
    expect(result.errors).toContainEqual({ phase: "termination", code: failure === "remove" ? "CONTAINER_REMOVAL_UNCONFIRMED" : "NAMESPACE_TERMINATION_UNCONFIRMED" });
    const retry = await runner.run(p.request, bounds);
    expect(retry).toMatchObject({ state: "containment-unavailable", pid: null, containment: { kind: "unavailable", reasonCode: "containment-ownership-unconfirmed" } });
    expect(proxy.owned.size).toBe(1);
  });

  it("keeps all approved values and original argv out of runtime control requests", async () => {
    const approved = "PRIVATE_TRANSPORT_VALUE", arg = "LITERAL_TARGET_ARGV";
    const p = await fixture("process.stdout.write(process.env.APPROVED+process.argv[2]);", { APPROVED: approved }, [arg]);
    const proxy = await runtimeProxy(dirname(p.source), "none");
    const runner = createReadinessContainedProcessRunner({ config: { ...config!, socketPath: proxy.socketPath }, target: p.target, approvedEnvNames: ["APPROVED"], assertArgv: () => undefined });
    const result = await runner.run(p.request, { ...bounds, redact: (text) => text.replaceAll(approved, "[redacted]") });
    expect(result, JSON.stringify(result)).toMatchObject({ succeeded: true, containment: { namespace: "terminated", cleanup: "removed" } });
    expect(proxy.observedControls).toHaveLength(1);
    const control = proxy.observedControls[0]!;
    expect(control).not.toContain(approved); expect(control).not.toContain(arg); expect(control).not.toContain("child.cjs");
    const ambient = JSON.parse(control).Env as string[];
    expect(ambient.length).toBeGreaterThan(0);
    expect(ambient).toContain("PATH=");
    expect(ambient.every((entry) => /^[A-Za-z_][A-Za-z0-9_]*=$/.test(entry))).toBe(true);
  });
});
