import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { createServer, request as httpRequest } from "node:http";
import type { Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverReadinessPlan } from "./audit-readiness.js";
import { bindReadinessPlanV1 } from "./audit-readiness-authority.js";
import { parseReadinessArtifactsV1 } from "./audit-readiness-artifacts.js";
import type { ReadinessExecutionV1, StageReceiptV1 } from "./audit-readiness-receipts.js";
import { executeBoundReadinessPlan } from "./audit-readiness-run.js";
import { captureSourceSentinel } from "./disposable-target.js";
import type { ReadinessContainmentConfig } from "./readiness-process-containment.js";

const config: ReadinessContainmentConfig | undefined = process.env.HARVEY_READINESS_DOCKER_SOCKET && process.env.HARVEY_READINESS_DOCKER_IMAGE ? {
  kind: "docker-local", socketPath: process.env.HARVEY_READINESS_DOCKER_SOCKET, imageId: process.env.HARVEY_READINESS_DOCKER_IMAGE,
} : undefined;
const roots: string[] = [];
const runtimeCleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  // Runtime cleanup must succeed before any mounted fixture can be deleted.
  for (const cleanup of runtimeCleanups.splice(0)) await cleanup();
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

function runtime(method: string, path: string): Promise<{ status: number; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ socketPath: config!.socketPath, method, path: `/v1.44${path}`, timeout: 5_000 }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.once("error", reject);
      res.once("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks) }));
    });
    req.once("timeout", () => req.destroy(new Error("Owned fixture runtime request timed out")));
    req.once("error", reject);
    req.end();
  });
}

type Fault = "inspect-after-start" | "remove" | "metadata" | "heartbeat";
interface OwnedContainer { id: string; root: string; labels: Record<string, string>; started: boolean }

async function runtimeProxy(fault: Fault) {
  const owned: OwnedContainer[] = [];
  const sockets = new Set<Socket>();
  const faults: string[] = [];
  const errors: unknown[] = [];
  const heartbeats: { running: boolean; pid: number; before: string; after: string }[] = [];
  const server = createServer((req, res) => {
    const id = /\/containers\/([a-f0-9]{64})(?:[/?]|$)/.exec(req.url ?? "")?.[1];
    const selected = owned.find((entry) => entry.id === id);
    const isCodegen = selected !== undefined && selected === owned[1];
    const inject = isCodegen && ((fault === "inspect-after-start" && selected.started && req.method === "GET" && req.url?.endsWith("/json"))
      || (fault === "remove" && req.method === "DELETE")
      || (fault === "metadata" && req.url?.includes("/archive?")));
    if (inject) { faults.push(`${req.method} ${req.url}`); res.writeHead(503); res.end("owned fixture runtime fault"); return; }
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.once("end", () => {
      void (async () => {
        if (isCodegen && fault === "heartbeat" && req.method === "DELETE") {
          const observation = await runtime("GET", `/containers/${selected.id}/json`);
          if (observation.status !== 200) throw new Error("Owned heartbeat container inspection failed");
          const state = (JSON.parse(observation.body.toString("utf8")) as { State: { Running: boolean; Pid: number } }).State;
          const heartbeat = join(selected.root, "target", "heartbeat");
          const before = await readFile(heartbeat, "utf8");
          await new Promise((resolve) => setTimeout(resolve, 200));
          heartbeats.push({ running: state.Running, pid: state.Pid, before, after: await readFile(heartbeat, "utf8") });
        }
        const raw = Buffer.concat(chunks);
        if (selected && req.url?.endsWith("/start")) selected.started = true;
        const upstream = httpRequest({ socketPath: config!.socketPath, path: req.url, method: req.method, headers: req.headers, timeout: 5_000 }, (response) => {
          res.writeHead(response.statusCode ?? 502, response.headers);
          const body: Buffer[] = [];
          response.on("data", (chunk: Buffer) => { if (req.url?.includes("/containers/create")) body.push(chunk); });
          response.once("end", () => {
            if (body.length && response.statusCode === 201) {
              const created = JSON.parse(Buffer.concat(body).toString("utf8")) as { Id: string };
              const control = JSON.parse(raw.toString("utf8")) as { Labels: Record<string, string>; HostConfig: { Mounts: { Source: string }[] } };
              if (/^[a-f0-9]{64}$/.test(created.Id)) owned.push({ id: created.Id, root: control.HostConfig.Mounts[0]!.Source, labels: control.Labels, started: false });
            }
          });
          response.pipe(res);
        });
        upstream.once("timeout", () => upstream.destroy(new Error("Fixture forwarding timed out")));
        upstream.once("error", (error) => { errors.push(error); if (!res.headersSent) res.writeHead(502); res.end(); });
        upstream.end(raw);
      })().catch((error: unknown) => { errors.push(error); if (!res.headersSent) res.writeHead(502); res.end(); });
    });
  });
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  server.on("upgrade", (req, downstream, head) => {
    const upstream = httpRequest({ socketPath: config!.socketPath, path: req.url, method: req.method, headers: req.headers, timeout: 5_000 });
    upstream.once("upgrade", (response, socket, upstreamHead) => {
      socket.setTimeout(0);
      sockets.add(socket); socket.once("close", () => sockets.delete(socket));
      downstream.write(`HTTP/1.1 ${response.statusCode} Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n`);
      if (upstreamHead.length) downstream.write(upstreamHead);
      if (head.length) socket.write(head);
      downstream.pipe(socket); socket.pipe(downstream);
      downstream.on("error", () => socket.destroy()); socket.on("error", () => downstream.destroy());
    });
    upstream.once("timeout", () => upstream.destroy(new Error("Fixture attach timed out")));
    upstream.once("error", (error) => { errors.push(error); downstream.destroy(); });
    upstream.end();
  });
  // A host-only short pathname avoids the macOS Unix socket pathname limit.
  const proxyRoot = await mkdtemp(join(process.platform === "darwin" ? "/private/tmp" : tmpdir(), "h-rdf-")); roots.push(proxyRoot);
  const socketPath = join(proxyRoot, "d.sock");
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(socketPath, resolve); });
  await chmod(socketPath, 0o600);
  runtimeCleanups.push(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    for (const entry of owned) {
      const current = await runtime("GET", `/containers/${entry.id}/json`);
      if (current.status === 404) continue;
      if (current.status !== 200) throw new Error("Cannot confirm owned fixture identity for cleanup");
      const inspected = JSON.parse(current.body.toString("utf8")) as { Id: string; Config: { Labels: Record<string, string> } };
      if (inspected.Id !== entry.id || !Object.keys(entry.labels).length || !Object.entries(entry.labels).every(([key, value]) => inspected.Config.Labels[key] === value)) throw new Error("Fixture container ownership changed");
      const removed = await runtime("DELETE", `/containers/${entry.id}?force=true&v=false`);
      if (removed.status !== 204 && removed.status !== 404) throw new Error("Owned fixture container removal failed");
      if ((await runtime("GET", `/containers/${entry.id}/json`)).status !== 404) throw new Error("Owned fixture container survived removal");
    }
  });
  return { socketPath, owned, faults, errors, heartbeats };
}

async function fixture(fault: Fault) {
  const parent = await realpath(process.env.HARVEY_READINESS_SHARED_PARENT ?? tmpdir());
  const root = await mkdtemp(join(parent, "harvey-readiness-flow-")); roots.push(root);
  const source = join(root, "source"); await mkdir(source);
  const pkg = { name: "readiness-containment-flow", version: "1.0.0", private: true, packageManager: "npm@10.9.2",
    scripts: { codegen: "node generator.cjs", build: "node builder.cjs", lint: "node linter.cjs" } };
  await writeFile(join(source, "package.json"), JSON.stringify(pkg));
  await writeFile(join(source, "package-lock.json"), JSON.stringify({ name: pkg.name, version: pkg.version, lockfileVersion: 3, packages: { "": pkg } }));
  await writeFile(join(source, "source-canary"), "source remains unchanged");
  const heartbeatChild = "setInterval(()=>require('node:fs').appendFileSync('heartbeat','tick\\n'),20)";
  const detached = `const fs=require('node:fs');const child=require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(heartbeatChild)}],{detached:true,stdio:'ignore'});child.unref();setInterval(()=>{if(fs.existsSync('heartbeat')&&fs.readFileSync('heartbeat','utf8').length>=10)process.exit(0);},10);setTimeout(()=>process.exit(2),2000).unref();`;
  for (const [kind, file] of Object.entries({ codegen: "generator.cjs", build: "builder.cjs", lint: "linter.cjs" })) {
    await writeFile(join(source, file), `require('node:fs').writeFileSync('${kind}.marker','executed'); process.stdout.write('${kind} ran'); ${kind === "codegen" && fault === "heartbeat" ? detached : ""}`);
  }
  const sentinel = await captureSourceSentinel(source);
  const plan = discoverReadinessPlan(source);
  const binding = bindReadinessPlanV1(plan, sentinel);
  const proxy = await runtimeProxy(fault);
  const run = () => executeBoundReadinessPlan({
    sourceRoot: source, plan, binding, allowTargetInstall: true,
    stageAuthorizations: plan.stages.filter((stage) => stage.assessment === "planned").map((stage) => ({
      stageId: stage.id, effect: stage.kind === "install" ? "target-install" : "disposable-local",
      source: "operator-reviewed generated containment fixture", reason: "Only disposable local marker files are written.",
      falsifier: "Original source changes or a stage reaches an external service.",
    })),
    approvedEnvNames: [], environment: {}, containment: { ...config!, socketPath: proxy.socketPath }, disposableTempParent: root,
    limits: { timeoutMs: 5_000, killGraceMs: 150, closeGraceMs: 400, headBytes: 2_048, tailBytes: 512 },
  });
  return { source, sentinel, plan, proxy, run };
}

function row(execution: ReadinessExecutionV1, kind: StageReceiptV1["kind"]) {
  const found = execution.stages.find((stage) => stage.kind === kind);
  if (!found) throw new Error(`Missing ${kind} stage`);
  return found;
}

async function assertSourceUnchanged(state: Awaited<ReturnType<typeof fixture>>) {
  expect(await readFile(join(state.source, "source-canary"), "utf8")).toBe("source remains unchanged");
  expect(await captureSourceSentinel(state.source)).toEqual(state.sentinel);
  expect(state.proxy.errors).toEqual([]);
}

describe.skipIf(!config)("complete readiness containment ownership flow (#1897)", () => {
  it.each(["inspect-after-start", "remove"] as const)("retains the copy and withholds independently ready lint after %s failure", async (fault) => {
    const state = await fixture(fault);
    const result = await state.run();
    const execution = result.execution;
    expect(row(execution, "install")).toMatchObject({ status: "passed", execution: { kind: "process" } });
    expect(row(execution, "codegen")).toMatchObject({ status: "failed", execution: { kind: "process", process: { succeeded: false,
      containment: { kind: "docker-pid-namespace", namespace: fault === "remove" ? "terminated" : "unconfirmed", cleanup: "retained" } } } });
    const lint = row(execution, "lint");
    expect(lint.prerequisiteStageIds).toEqual([row(execution, "install").stageId]);
    for (const kind of ["lint", "build"] as const) expect(row(execution, kind)).toMatchObject({
      status: "not-assessed", authority: null, execution: { kind: "not-run" }, diagnostic: { reasonCode: "owned-workload-unconfirmed" },
    });
    expect(execution.status).toBe("failed");
    expect(state.proxy.faults.length).toBeGreaterThan(0);
    expect(state.proxy.owned).toHaveLength(2);
    expect(state.proxy.owned.every((entry) => entry.started)).toBe(true);
    const owned = state.proxy.owned[1]!;
    expect(row(execution, "codegen")).toMatchObject({ execution: { process: { containment: { containerId: owned.id } } } });
    expect(execution.cleanup.root).toBe(owned.root);
    expect((await lstat(owned.root)).isDirectory()).toBe(true);
    expect(execution.cleanup).toMatchObject({ status: "failed", removal: { status: "failed", reasonCode: "owned-workload-unconfirmed" }, source: { status: "passed" } });
    expect(await readFile(join(owned.root, "target", "codegen.marker"), "utf8")).toBe("executed");
    await expect(lstat(join(owned.root, "target", "lint.marker"))).rejects.toMatchObject({ code: "ENOENT" });
    const retained = await runtime("GET", `/containers/${owned.id}/json`);
    expect(retained.status).toBe(200);
    expect(JSON.parse(retained.body.toString("utf8"))).toMatchObject({ Id: owned.id, Config: { Labels: owned.labels } });
    expect(parseReadinessArtifactsV1({ descriptorJson: result.descriptorJson, executionJson: result.json }).execution).toEqual(execution);
    await assertSourceUnchanged(state);
  });

  it("stops a detached stdio-ignore heartbeat before releasing the copy for cleanup", async () => {
    const state = await fixture("heartbeat");
    const result = await state.run();
    expect(state.proxy.errors).toEqual([]);
    for (const kind of ["install", "codegen", "build", "lint"] as const) expect(row(result.execution, kind)).toMatchObject({
      status: "passed", execution: { kind: "process", process: { succeeded: true, exit: { code: 0, signal: null }, close: { code: 0, signal: null },
        containment: { namespace: "terminated", terminalObservation: { running: false, pid: 0 }, metadata: "verified", cleanup: "removed" } } },
    });
    expect(state.proxy.heartbeats).toHaveLength(1);
    const observation = state.proxy.heartbeats[0]!;
    expect(observation).toMatchObject({ running: false, pid: 0 });
    expect(observation.before.length).toBeGreaterThan(0);
    expect(observation.after).toBe(observation.before);
    expect(result.execution.cleanup).toMatchObject({ status: "passed", removal: { status: "removed" }, source: { status: "passed" } });
    expect(state.proxy.owned).toHaveLength(4);
    for (const owned of state.proxy.owned) expect((await runtime("GET", `/containers/${owned.id}/json`)).status).toBe(404);
    await expect(lstat(state.proxy.owned[0]!.root)).rejects.toMatchObject({ code: "ENOENT" });
    expect(parseReadinessArtifactsV1({ descriptorJson: result.descriptorJson, executionJson: result.json }).execution).toEqual(result.execution);
    await assertSourceUnchanged(state);
  });

  it("cleans a confirmed terminated namespace despite missing metadata while preserving a failed stage", async () => {
    const state = await fixture("metadata");
    const result = await state.run();
    expect(row(result.execution, "codegen")).toMatchObject({ status: "failed", execution: { kind: "process", process: {
      succeeded: false, pid: null, exit: null, close: null,
      containment: { namespace: "terminated", terminalObservation: { running: false, pid: 0 }, metadata: "unavailable", cleanup: "removed" },
    } } });
    expect(row(result.execution, "build")).toMatchObject({ status: "not-assessed", diagnostic: { reasonCode: "prerequisite-not-passed" } });
    expect(row(result.execution, "lint")).toMatchObject({ status: "passed", execution: { kind: "process" } });
    expect(result.execution.status).toBe("failed");
    expect(result.execution.cleanup).toMatchObject({ status: "passed", removal: { status: "removed" }, source: { status: "passed" } });
    expect(state.proxy.owned).toHaveLength(3);
    expect(state.proxy.faults).toHaveLength(1);
    for (const owned of state.proxy.owned) expect((await runtime("GET", `/containers/${owned.id}/json`)).status).toBe(404);
    await expect(lstat(state.proxy.owned[0]!.root)).rejects.toMatchObject({ code: "ENOENT" });
    expect(parseReadinessArtifactsV1({ descriptorJson: result.descriptorJson, executionJson: result.json }).execution).toEqual(result.execution);
    await assertSourceUnchanged(state);
  });
});
