import { createHash, randomBytes } from "node:crypto";
import { lstat, realpath, unlink, writeFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { isAbsolute, join, relative, sep } from "node:path";
import type { Socket } from "node:net";
import type { ReadinessSpawnRequest } from "./audit-readiness-authority.js";
import { BoundedOutputCapture, configureBoundedProcess, validateBoundedProcessRequest, type BoundedProcessOptions, type BoundedProcessResult, type ReadinessProcessContainment } from "./bounded-process.js";
import { verifyRunRoot, type DisposableTarget } from "./disposable-target.js";

export interface ReadinessContainmentConfig {
  kind: "docker-local";
  socketPath: string;
  imageId: string;
  /** Absolute paths in the operator-selected immutable image, never host mounts. */
  nodePath?: string;
  envPath?: string;
  toolchainPath?: string;
}

export type ReadinessContainmentAvailability =
  | { status: "ready"; runtimeVersion: string; apiVersion: string; imageId: string; toolchainPath: string }
  | { status: "unavailable"; reasonCode: string; reason: string; falsifier: string };

type ContainerEvidence = Extract<ReadinessProcessContainment, { kind: "docker-pid-namespace" }>;
type Bounds = ReturnType<typeof configureBoundedProcess>;
type Ready = Extract<ReadinessContainmentAvailability, { status: "ready" }>;
const API = "1.44";
const CONTROL_TIMEOUT = 5_000;
const REQUEST_LIMIT = 1024 * 1024;
const CONTROL_LIMIT = 128 * 1024;
const OWNER_LABEL = "org.harvey.readiness.owner";
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const CONTAINER_ID = /^[a-f0-9]{64}$/;
const SYSTEM_CODES = new Set(["EACCES", "EAGAIN", "EBADF", "E2BIG", "EFAULT", "EINTR", "EINVAL", "EIO", "EISDIR", "ELOOP", "EMFILE", "ENAMETOOLONG", "ENFILE", "ENOENT", "ENOEXEC", "ENOMEM", "ENOSYS", "ENOTDIR", "EPERM", "EPIPE", "ESRCH", "ETXTBSY"]);

function safeCode(error: unknown): string {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  return typeof code === "string" && SYSTEM_CODES.has(code) ? code : "RUNTIME_OPERATION_FAILED";
}

class RuntimeFailure extends Error {
  constructor(readonly code: string, readonly httpStatus?: number) { super(code); }
}

function unavailable(code: string): ReadinessContainmentAvailability {
  return { status: "unavailable", reasonCode: code, reason: "A verified local process-containment runtime is unavailable; no target command is permitted.", falsifier: "Provide an operator-approved local Unix socket, an already present immutable Linux image with the configured env/Node tools, and a runtime-visible disposable root, then retry." };
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new RuntimeFailure("RUNTIME_RESPONSE_INVALID");
  return value as Record<string, unknown>;
}

function absolute(path: unknown): path is string { return typeof path === "string" && isAbsolute(path) && !path.includes("\0") && path !== "/"; }
function confined(root: string, path: string): boolean { const rel = relative(root, path); return rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`)); }
function timestamp(): string { return new Date().toISOString(); }
function delay(ms: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, ms)); }

function configuration(input: ReadinessContainmentConfig | undefined): Required<ReadinessContainmentConfig> | null {
  if (input === undefined) return null;
  if (!input || Object.keys(input).some((key) => !["kind", "socketPath", "imageId", "nodePath", "envPath", "toolchainPath"].includes(key))
    || input.kind !== "docker-local" || !absolute(input.socketPath) || !SHA256.test(input.imageId)
    || (input.nodePath !== undefined && !absolute(input.nodePath)) || (input.envPath !== undefined && !absolute(input.envPath))) {
    throw new Error("Readiness containment requires a trusted local Unix socket and immutable image ID.");
  }
  const result = { ...input, nodePath: input.nodePath ?? "/usr/local/bin/node", envPath: input.envPath ?? "/usr/bin/env", toolchainPath: input.toolchainPath ?? "/usr/local/bin:/usr/bin:/bin" };
  if (!result.toolchainPath.split(":").every(absolute)) throw new Error("Readiness containment requires absolute image toolchain directories.");
  return Object.freeze(result);
}

/** A fixed deadline covers connect, response headers and body; runtime text is never an error. */
class DockerLocal {
  constructor(readonly socketPath: string) {}

  async bytes(method: string, path: string, body?: unknown, limit = CONTROL_LIMIT): Promise<Buffer> {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    return new Promise<Buffer>((resolve, reject) => {
      let finished = false;
      const chunks: Buffer[] = [];
      let length = 0;
      const finish = (error?: unknown) => {
        if (finished) return;
        finished = true; clearTimeout(timer);
        if (error) { req.destroy(); reject(error); } else resolve(Buffer.concat(chunks));
      };
      const req = httpRequest({ socketPath: this.socketPath, method, path, headers: payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {} }, (res) => {
        if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) { res.destroy(); finish(new RuntimeFailure("RUNTIME_HTTP_FAILURE", res.statusCode)); return; }
        res.on("data", (chunk: Buffer) => {
          length += chunk.length;
          if (length > limit) { res.destroy(); finish(new RuntimeFailure("RUNTIME_RESPONSE_LIMIT")); return; }
          chunks.push(chunk);
        });
        res.once("end", () => finish());
        res.once("error", () => finish(new RuntimeFailure("RUNTIME_RESPONSE_INTERRUPTED")));
        res.once("aborted", () => finish(new RuntimeFailure("RUNTIME_RESPONSE_INTERRUPTED")));
      });
      const timer = setTimeout(() => finish(new RuntimeFailure("RUNTIME_OPERATION_TIMEOUT")), CONTROL_TIMEOUT);
      req.once("error", (error) => finish(new RuntimeFailure(safeCode(error))));
      req.end(payload);
    });
  }

  async json(method: string, path: string, body?: unknown): Promise<Record<string, unknown>> {
    try { return record(JSON.parse((await this.bytes(method, path, body)).toString("utf8"))); }
    catch (error) { if (error instanceof RuntimeFailure) throw error; throw new RuntimeFailure("RUNTIME_RESPONSE_INVALID"); }
  }

  async attach(id: string, onData: (stream: 1 | 2, bytes: Buffer) => void): Promise<{ send: (bytes: Buffer) => void; done: Promise<boolean>; destroy: () => void }> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const req = httpRequest({ socketPath: this.socketPath, method: "POST", path: `/v${API}/containers/${id}/attach?stream=1&stdin=1&stdout=1&stderr=1`, headers: { Connection: "Upgrade", Upgrade: "tcp" } });
      const fail = () => { if (!settled) { settled = true; clearTimeout(timer); req.destroy(); reject(new RuntimeFailure("RUNTIME_ATTACH_FAILED")); } };
      const timer = setTimeout(fail, CONTROL_TIMEOUT);
      req.once("error", fail);
      req.once("response", (res) => { res.destroy(); fail(); });
      req.once("upgrade", (res, socket: Socket, head) => {
        if (settled || res.statusCode !== 101) { socket.destroy(); fail(); return; }
        settled = true; clearTimeout(timer);
        let pending: Buffer = Buffer.alloc(0);
        let complete = false;
        let ended = false;
        let finish!: (value: boolean) => void;
        const done = new Promise<boolean>((resolveDone) => { finish = resolveDone; });
        const consume = (chunk: Buffer) => {
          pending = Buffer.concat([pending, chunk]);
          while (pending.length >= 8) {
            const length = pending.readUInt32BE(4);
            const stream = pending[0];
            if ((stream !== 1 && stream !== 2) || pending[1] !== 0 || pending[2] !== 0 || pending[3] !== 0 || length > REQUEST_LIMIT) { socket.destroy(); return; }
            if (pending.length < length + 8) return;
            try { onData(stream, pending.subarray(8, length + 8)); } catch { socket.destroy(); return; }
            pending = pending.subarray(length + 8);
          }
        };
        socket.on("data", consume);
        socket.once("end", () => { ended = true; complete = pending.length === 0; finish(complete); });
        socket.once("error", () => finish(false));
        socket.once("close", () => { if (!ended) finish(false); });
        if (head.length) consume(head);
        resolve({ send: (bytes) => { socket.end(bytes); }, done, destroy: () => { socket.destroy(); finish(false); } });
      });
      req.end();
    });
  }
}

// This literal is the only program in container control argv. Target values arrive on stdin.
// PID 1 owns the control directory; child uid/gid cannot alter metadata or signal the observer.
const OBSERVER = String.raw`
const fs=require('node:fs'), cp=require('node:child_process'), crypto=require('node:crypto'),path=require('node:path');
const MAX=1048576, codes=new Set(['EACCES','EAGAIN','EBADF','E2BIG','EFAULT','EINTR','EINVAL','EIO','EISDIR','ELOOP','EMFILE','ENAMETOOLONG','ENFILE','ENOENT','ENOEXEC','ENOMEM','ENOSYS','ENOTDIR','EPERM','EPIPE','ESRCH','ETXTBSY']);
const at=()=>new Date().toISOString(), safe=e=>codes.has(e&&e.code)?e.code:'UNKNOWN';
let input=[],size=0,finished=false,child,dir,deadline,force,closing;
let m={version:1,requestSha256:null,pid:null,spawnedAt:null,exit:null,close:null,state:'exited',errors:[],reason:null,attempts:[],stdoutEnded:false,stderrEnded:false,forced:false,identity:null,nodeVersion:process.version};
const save=()=>{if(dir){fs.writeFileSync(dir+'/pending',JSON.stringify(m),{mode:0o600});fs.renameSync(dir+'/pending',dir+'/result.json');}};
const finish=()=>{if(finished)return;finished=true;clearTimeout(deadline);clearTimeout(force);clearTimeout(closing);save();let n=0;const end=()=>{if(++n===2){save();process.exit(0);}};process.stdout.write('',end);process.stderr.write('',end);setTimeout(()=>process.exit(1),1000);};
// kill permission uses the sender's effective UID and the receiver's real/saved UID.
// Keep our real/saved UID root, changing only euid synchronously; no CAP_KILL is granted.
const signal=s=>{if(!child||!child.pid)return;let status='sent',code=null;try{process.seteuid(q.uid);try{process.kill(-child.pid,s);}finally{process.seteuid(0);}}catch(e){code=safe(e);status=code==='ESRCH'?'absent':'failed';}m.attempts.push({at:at(),signal:s,status,code});save();};
const terminate=(reason,state)=>{if(finished||m.reason)return;m.reason=reason;m.state=state;signal('SIGTERM');force=setTimeout(()=>signal('SIGKILL'),q.killGraceMs);closing=setTimeout(()=>{m.forced=!m.close;child?.stdout?.destroy();child?.stderr?.destroy();finish();},q.killGraceMs+q.closeGraceMs);};
process.on('SIGTERM',()=>{if(child)terminate('abort','aborted');else finish();});
process.on('uncaughtException',()=>{m.state='observer-error';m.errors.push({phase:'observer',code:'OBSERVER_FAILED'});if(child)terminate('observer-error','observer-error');else finish();});
let q,prerequisite='OBSERVER_PREREQUISITE_FAILED';
process.stdin.on('data',b=>{size+=b.length;if(size>MAX)process.exit(2);input.push(b);});
process.stdin.on('end',()=>{
 try{
  const raw=Buffer.concat(input);input=[];q=JSON.parse(raw.toString('utf8'));m.requestSha256=crypto.createHash('sha256').update(raw).digest('hex');
  if(process.pid!==1||process.getuid()!==0||!/^[a-f0-9]{32}$/.test(q.nonce))throw Error();
  dir='/.harvey-readiness-'+q.nonce;fs.mkdirSync(dir,{mode:0o700});process.setgroups([]);
  if(!Number.isSafeInteger(q.uid)||q.uid<=0||!Number.isSafeInteger(q.gid)||q.gid<0||!q.request||!Array.isArray(q.approvedEnvNames))throw Error();
  const r=q.request, argv=[r.bin,...r.args];
  if(r.shell!==false||argv.some(x=>typeof x!=='string'||x.includes('\0'))||q.approvedEnvNames.some(n=>typeof n!=='string'||(r.env[n]&&argv.some(a=>a.includes(r.env[n])))))throw Error();
  if(fs.readFileSync(q.root+'/.harvey-mount-'+q.nonce,'utf8')!==q.nonce)throw Error();fs.unlinkSync(q.root+'/.harvey-mount-'+q.nonce);
  prerequisite='IMAGE_TOOLCHAIN_UNTRUSTED';
  const imagePath=(p,directory)=>{const resolved=fs.realpathSync(p);if(resolved===q.root||resolved.startsWith(q.root+'/')||resolved===dir||resolved.startsWith(dir+'/'))throw Error();const s=fs.statSync(resolved);if(directory?!s.isDirectory():!s.isFile())throw Error();let current=resolved;for(;;){const entry=fs.statSync(current);if(entry.uid!==0||(entry.mode&0o022)!==0)throw Error();if(current==='/')break;current=path.dirname(current);}return resolved;};
  const search=r.env.PATH.split(':');for(const p of search){if(!path.isAbsolute(p))throw Error();imagePath(p,true);}
  const candidates=r.bin.includes('/')?[r.bin]:search.map(p=>path.join(p,r.bin));for(const p of candidates){try{fs.accessSync(p,fs.constants.X_OK);}catch(e){if(e.code==='ENOENT'||e.code==='ENOTDIR'||e.code==='EACCES')continue;throw e;}imagePath(p,false);break;}
  prerequisite='OBSERVER_PREREQUISITE_FAILED';
  save();
  child=cp.spawn(r.bin,r.args,{cwd:r.cwd,env:r.env,shell:false,detached:true,uid:q.uid,gid:q.gid,stdio:['ignore','pipe','pipe']});
  child.once('spawn',()=>{
   m.pid=child.pid;m.spawnedAt=at();
   try{const status=fs.readFileSync('/proc/'+child.pid+'/status','utf8');const uid=status.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m);const gid=status.match(/^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m);const cap=status.match(/^CapEff:\s+(\w+)/m);const nnp=status.match(/^NoNewPrivs:\s+(\d+)/m);if(!uid||!gid||uid.slice(1).some(x=>Number(x)!==q.uid)||gid.slice(1).some(x=>Number(x)!==q.gid)||cap?.[1]!=='0000000000000000'||nnp?.[1]!=='1')throw Error();m.identity={uid:q.uid,gid:q.gid,capEff:cap[1],noNewPrivileges:true};}
   catch{m.errors.push({phase:'observer',code:'TARGET_IDENTITY_UNVERIFIED'});terminate('observer-error','observer-error');}
   save();
  });
  child.on('error',e=>{m.state='spawn-error';m.errors.push({phase:'spawn',code:safe(e)});save();});
  child.once('exit',(code,signal)=>{m.exit={at:at(),code,signal};save();if(!closing)closing=setTimeout(()=>{if(!m.close){m.forced=true;m.reason=m.reason||'descendants';m.state=m.state==='exited'?'descendant-cleanup':m.state;child.stdout.destroy();child.stderr.destroy();finish();}},q.closeGraceMs);});
  child.once('close',(code,signal)=>{m.close={at:at(),code,signal};save();finish();});
  for(const [name,dest] of [['stdout',process.stdout],['stderr',process.stderr]]){const s=child[name];s.pipe(dest,{end:false});s.once('end',()=>{m[name+'Ended']=true;save();});s.on('error',e=>{m.errors.push({phase:name,code:safe(e)});terminate('io-error','io-error');});}
  deadline=setTimeout(()=>terminate('timeout','timed-out'),q.timeoutMs);
 }catch{m.state='containment-unavailable';m.errors.push({phase:'observer',code:prerequisite});finish();}
});
setTimeout(()=>{if(!q)process.exit(2);},5000).unref();
`;

function terminal(inspection: Record<string, unknown>): boolean {
  const state = record(inspection.State);
  return state.Running === false && state.Pid === 0 && state.Paused === false && state.Restarting === false && ["created", "exited", "dead"].includes(state.Status as string);
}

function requireTerminal(inspection: Record<string, unknown>): void {
  if (!terminal(inspection)) throw new RuntimeFailure("NAMESPACE_TERMINATION_UNCONFIRMED");
}

function owned(inspection: Record<string, unknown>, nonce: string, expectedId?: string): string {
  const id = inspection.Id;
  if (typeof id !== "string" || !CONTAINER_ID.test(id) || (expectedId !== undefined && id !== expectedId)
    || record(record(inspection.Config).Labels)[OWNER_LABEL] !== nonce) throw new RuntimeFailure("CONTAINER_OWNERSHIP_UNVERIFIED");
  return id;
}

function isolated(inspection: Record<string, unknown>, config: Required<ReadinessContainmentConfig>, root: string): void {
  const host = record(inspection.HostConfig);
  const security = host.SecurityOpt;
  const mounts = inspection.Mounts;
  if (inspection.Image !== config.imageId || host.Privileged !== false || host.PidMode !== "" || host.NetworkMode !== "none"
    || host.ReadonlyRootfs !== false || host.PidsLimit !== 64 || host.Memory !== 512 * 1024 * 1024
    || JSON.stringify(host.CapDrop) !== '["ALL"]' || JSON.stringify(host.CapAdd) !== '["SETUID","SETGID"]'
    || !Array.isArray(security) || !security.includes("no-new-privileges") || host.AutoRemove !== false
    || !Array.isArray(mounts) || mounts.length !== 1 || record(mounts[0]).Type !== "bind" || record(mounts[0]).Source !== root || record(mounts[0]).Destination !== root
    || record(record(inspection.Config).Healthcheck).Test?.toString() !== "NONE") throw new RuntimeFailure("CONTAINER_ISOLATION_UNVERIFIED");
}

interface Metadata {
  version: 1; requestSha256: string; pid: number | null; spawnedAt: string | null;
  exit: BoundedProcessResult["exit"]; close: BoundedProcessResult["close"];
  state: BoundedProcessResult["state"]; errors: BoundedProcessResult["errors"];
  reason: BoundedProcessResult["termination"]["reason"]; attempts: BoundedProcessResult["termination"]["attempts"];
  stdoutEnded: boolean; stderrEnded: boolean; forced: boolean;
  identity: ContainerEvidence["targetIdentity"]; nodeVersion: string;
}

/** Docker archive extraction is bounded and accepts only the single private root-owned regular file. */
function metadataFromArchive(bytes: Buffer, digest: string, uid: number, gid: number): Metadata {
  const header = bytes.subarray(0, 512);
  const field = (start: number, length: number) => header.subarray(start, start + length).toString("utf8").replace(/\0.*$/s, "").trim();
  const size = Number.parseInt(field(124, 12), 8);
  if (header.length !== 512 || field(0, 100) !== "result.json" || !["", "0"].includes(field(156, 1)) || Number.parseInt(field(108, 8), 8) !== 0
    || Number.parseInt(field(116, 8), 8) !== 0 || Number.parseInt(field(100, 8), 8) !== 0o600 || !Number.isSafeInteger(size) || size < 1 || size > 32 * 1024 || bytes.length < 512 + size) throw new RuntimeFailure("OBSERVER_METADATA_INVALID");
  let value: Record<string, unknown>;
  try { value = record(JSON.parse(bytes.subarray(512, 512 + size).toString("utf8"))); }
  catch { throw new RuntimeFailure("OBSERVER_METADATA_INVALID"); }
  const date = (v: unknown) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
  if (value.version !== 1 || value.requestSha256 !== digest || !["exited", "timed-out", "aborted", "spawn-error", "io-error", "observer-error", "descendant-cleanup", "containment-unavailable"].includes(value.state as string)
    || (value.pid !== null && (!Number.isSafeInteger(value.pid) || Number(value.pid) < 2)) || (value.spawnedAt !== null && !date(value.spawnedAt))
    || (value.pid === null) !== (value.spawnedAt === null) || !Array.isArray(value.errors) || !Array.isArray(value.attempts)
    || ![null, "timeout", "abort", "process-error", "io-error", "observer-error", "descendants"].includes(value.reason as null)
    || [value.stdoutEnded, value.stderrEnded, value.forced].some((v) => typeof v !== "boolean") || typeof value.nodeVersion !== "string" || !/^v\d+\.\d+\.\d+$/.test(value.nodeVersion)) throw new RuntimeFailure("OBSERVER_METADATA_INVALID");
  for (const v of [value.exit, value.close]) {
    if (v === null) continue;
    const end = record(v);
    if (!date(end.at) || (end.code !== null && !Number.isSafeInteger(end.code)) || (end.signal !== null && (typeof end.signal !== "string" || !/^SIG[A-Z0-9]+$/.test(end.signal)))) throw new RuntimeFailure("OBSERVER_METADATA_INVALID");
  }
  for (const e of value.errors) {
    const error = record(e);
    if (!["spawn", "stdout", "stderr", "observer"].includes(error.phase as string) || typeof error.code !== "string" || !/^[A-Z0-9_]+$/.test(error.code)) throw new RuntimeFailure("OBSERVER_METADATA_INVALID");
  }
  for (const item of value.attempts) {
    const attempt = record(item);
    if (!date(attempt.at) || !["SIGTERM", "SIGKILL"].includes(attempt.signal as string) || !["sent", "absent", "failed"].includes(attempt.status as string) || (attempt.code !== null && (typeof attempt.code !== "string" || !/^[A-Z0-9_]+$/.test(attempt.code)))) throw new RuntimeFailure("OBSERVER_METADATA_INVALID");
  }
  if (value.identity !== null) {
    const identity = record(value.identity);
    if (identity.uid !== uid || identity.gid !== gid || identity.capEff !== "0000000000000000" || identity.noNewPrivileges !== true) throw new RuntimeFailure("OBSERVER_METADATA_INVALID");
  }
  return value as unknown as Metadata;
}

export function createReadinessContainedProcessRunner(options: {
  config?: ReadinessContainmentConfig;
  target: DisposableTarget;
  approvedEnvNames: readonly string[];
  /** Must be the receipt/admission approved-value guard; invoked again at the private transport boundary. */
  assertArgv: (request: ReadinessSpawnRequest) => void;
}): { probe(): Promise<ReadinessContainmentAvailability>; run(request: ReadinessSpawnRequest, bounds: BoundedProcessOptions): Promise<BoundedProcessResult> } {
  const config = configuration(options.config);
  if (typeof options.assertArgv !== "function" || !Array.isArray(options.approvedEnvNames) || options.approvedEnvNames.some((name) => !/^[A-Z][A-Z0-9_]*$/.test(name))) throw new Error("Readiness containment requires an explicit approved-value guard and environment names.");
  const approvedEnvNames = Object.freeze([...new Set(options.approvedEnvNames)]);
  let active = false;
  let poisoned = false;
  let imageEnvNames: string[] = [];

  async function probe(): Promise<ReadinessContainmentAvailability> {
    if (!config) return unavailable("containment-not-configured");
    if (process.platform !== "linux" && process.platform !== "darwin") return unavailable("containment-platform-unsupported");
    try {
      const path = await realpath(config.socketPath);
      const info = await lstat(path);
      if (!info.isSocket() || (info.uid !== 0 && info.uid !== process.getuid?.()) || (info.mode & 0o022) !== 0 || confined(options.target.root, path) || confined(options.target.sourceRoot, path)) return unavailable("containment-socket-untrusted");
      const client = new DockerLocal(path);
      const version = await client.json("GET", "/version");
      if (version.Os !== "linux" || typeof version.Version !== "string" || !/^\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?$/.test(version.Version)
        || typeof version.ApiVersion !== "string" || Number(version.ApiVersion) < Number(API) || (typeof version.MinAPIVersion === "string" && Number(version.MinAPIVersion) > Number(API))) return unavailable("containment-runtime-unsupported");
      const image = await client.json("GET", `/v${API}/images/${config.imageId}/json`);
      const imageConfig = record(image.Config);
      if (image.Id !== config.imageId || image.Os !== "linux" || (imageConfig.Volumes !== null && imageConfig.Volumes !== undefined && Object.keys(record(imageConfig.Volumes)).length > 0)) return unavailable("containment-image-unsupported");
      if (imageConfig.Env !== null && imageConfig.Env !== undefined && (!Array.isArray(imageConfig.Env) || imageConfig.Env.some((entry) => typeof entry !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*=/.test(entry)))) return unavailable("containment-image-environment-invalid");
      imageEnvNames = (imageConfig.Env as string[] | null | undefined ?? []).map((entry) => entry.slice(0, entry.indexOf("=")));
      return { status: "ready", runtimeVersion: version.Version, apiVersion: API, imageId: config.imageId, toolchainPath: config.toolchainPath };
    } catch { return unavailable("containment-runtime-unavailable"); }
  }

  async function run(request: ReadinessSpawnRequest, input: BoundedProcessOptions): Promise<BoundedProcessResult> {
    validateBoundedProcessRequest(request);
    const bounds = configureBoundedProcess(input);
    const started = performance.now(), startedAt = timestamp();
    const overlap = Math.min(64 * 1024, Math.max(1024, ...Object.values(request.env).map((value) => Buffer.byteLength(value))));
    const stdout = new BoundedOutputCapture(bounds.output.headBytes, bounds.output.tailBytes, overlap);
    const stderr = new BoundedOutputCapture(bounds.output.headBytes, bounds.output.tailBytes, overlap);
    const result: BoundedProcessResult = {
      state: "containment-unavailable", succeeded: false, containment: { kind: "unavailable", reasonCode: "containment-not-configured" }, pid: null,
      queuedAt: startedAt, startedAt, spawnedAt: null, firstByteAt: null, endedAt: startedAt,
      queueDurationMs: 0, durationMs: 0, fromFirstByteMs: null, exit: null, close: null, errors: [],
      termination: { reason: null, attempts: [], tree: "not-started", stdioForcedClosed: false },
      stdout: undefined as unknown as BoundedProcessResult["stdout"], stderr: undefined as unknown as BoundedProcessResult["stderr"],
    };
    let firstByte: number | null = null;
    const finish = () => {
      const redactionError = () => { result.succeeded = false; result.errors.push({ phase: "redaction", code: "REDACTION_FAILED" }); if (result.state === "exited") result.state = "redaction-error"; };
      result.stdout = stdout.finish("stdout", bounds.redact, redactionError, result.spawnedAt !== null, result.termination.stdioForcedClosed);
      result.stderr = stderr.finish("stderr", bounds.redact, redactionError, result.spawnedAt !== null, result.termination.stdioForcedClosed);
      result.endedAt = timestamp(); result.durationMs = Math.max(0, performance.now() - started); result.fromFirstByteMs = firstByte === null ? null : Math.max(0, performance.now() - firstByte);
      result.succeeded = result.state === "exited" && result.pid !== null && result.exit?.code === 0 && result.exit.signal === null && result.close?.code === 0 && result.close.signal === null
        && result.errors.length === 0 && result.termination.reason === null && result.termination.tree === "absent" && !result.termination.stdioForcedClosed
        && result.containment.kind === "docker-pid-namespace" && result.containment.namespace === "terminated" && result.containment.isolationVerified && result.containment.metadata === "verified" && result.containment.cleanup === "removed" && result.containment.targetIdentity !== null
        && [result.stdout, result.stderr].every((stream) => stream.complete && !stream.truncated && !stream.redactionTruncated);
      return result;
    };
    if (active || poisoned) { result.containment = { kind: "unavailable", reasonCode: poisoned ? "containment-ownership-unconfirmed" : "containment-run-active" }; return finish(); }
    if (bounds.signal?.aborted) { result.state = "aborted"; result.termination.reason = "abort"; return finish(); }
    active = true;
    try {
      const ready = await probe();
      if (ready.status !== "ready" || !config) { result.containment = { kind: "unavailable", reasonCode: ready.status === "unavailable" ? ready.reasonCode : "containment-not-configured" }; return finish(); }
      await executeContained(config, ready, imageEnvNames, options.target, request, bounds, approvedEnvNames, options.assertArgv, result, (stream, bytes) => {
        (stream === 1 ? stdout : stderr).write(bytes);
        if (firstByte === null && bytes.length > 0) { firstByte = performance.now(); result.firstByteAt = timestamp(); bounds.onFirstByte?.(); }
      });
      if (result.containment.kind === "docker-pid-namespace") {
        poisoned = result.containment.namespace === "unconfirmed" || result.containment.cleanup === "retained";
        stdout.ended = result.containment.metadata === "verified" && !result.termination.stdioForcedClosed;
        stderr.ended = stdout.ended;
      }
      return finish();
    } catch {
      result.errors.push({ phase: "observer", code: "CONTAINMENT_BOUNDARY_UNVERIFIED" });
      if (result.containment.kind === "docker-pid-namespace" && result.containment.namespace !== "not-started") { poisoned = true; result.state = "termination-unconfirmed"; result.termination.tree = "unconfirmed"; result.termination.stdioForcedClosed = true; }
      return finish();
    } finally { active = false; }
  }
  return Object.freeze({ probe, run });
}

async function executeContained(config: Required<ReadinessContainmentConfig>, ready: Ready, imageEnvNames: readonly string[], target: DisposableTarget, request: ReadinessSpawnRequest, bounds: Bounds, approvedEnvNames: readonly string[], assertArgv: (request: ReadinessSpawnRequest) => void, result: BoundedProcessResult, onData: (stream: 1 | 2, bytes: Buffer) => void): Promise<void> {
  const root = await verifyRunRoot(target, relative(target.targetRoot, request.cwd).split(sep).join("/") || ".");
  if (root.status !== "verified" || root.cwd !== request.cwd || request.env.PATH !== config.toolchainPath || !confined(target.root, request.cwd)
    || [config.nodePath, config.envPath, ...config.toolchainPath.split(":")].some((path) => confined(target.root, path) || confined(target.sourceRoot, path))) { result.containment = { kind: "unavailable", reasonCode: "containment-request-boundary-invalid" }; return; }
  const uid = process.getuid?.(), gid = process.getgid?.();
  if (uid === undefined || uid === 0 || gid === undefined) { result.containment = { kind: "unavailable", reasonCode: "containment-target-identity-unavailable" }; return; }
  const nonce = randomBytes(16).toString("hex");
  const name = `harvey-readiness-${nonce}`;
  const client = new DockerLocal(await realpath(config.socketPath));
  const evidence: ContainerEvidence = {
    kind: "docker-pid-namespace", imageId: config.imageId, containerId: null, leaseName: name, runtimeVersion: ready.runtimeVersion, apiVersion: ready.apiVersion,
    namespace: "not-started", targetWork: "not-started", terminalObservation: null, metadata: "unavailable", cleanup: "not-required", isolationVerified: false,
    isolation: { privatePidNamespace: true, network: "none", noNewPrivileges: true, capDrop: "ALL", observerCapabilities: ["SETUID", "SETGID"], targetUid: uid, targetGid: gid, mountScope: "disposable-root-only", rootfs: "private-writable-overlay" },
    targetIdentity: null, observerNodeVersion: null,
  };
  result.containment = evidence;
  let attachment: Awaited<ReturnType<DockerLocal["attach"]>> | undefined;
  let creationAttempted = false, startAttempted = false, streamComplete = false;
  let markerCreated = false;
  let digest = "";
  let parentFailure: "abort" | "timeout" | "observer-error" | null = null;
  const observedFailure = (): "abort" | "timeout" | "observer-error" | null => parentFailure;
  let timer: NodeJS.Timeout | undefined;
  let wake!: () => void;
  const interrupted = new Promise<void>((resolve) => { wake = resolve; });
  const abort = () => { parentFailure ??= "abort"; wake(); };
  const error = (phase: "spawn" | "observer" | "termination", code: string) => result.errors.push({ phase, code });
  const inspect = async () => {
    const view = await client.json("GET", `/v${API}/containers/${evidence.containerId ?? name}/json`);
    evidence.containerId = owned(view, nonce, evidence.containerId ?? undefined);
    return view;
  };
  const kill = async (signal: "SIGTERM" | "SIGKILL") => {
    if (!evidence.containerId) return;
    try {
      const view = await inspect();
      if (terminal(view)) return;
      await client.bytes("POST", `/v${API}/containers/${evidence.containerId}/kill?signal=${signal}`);
    } catch { error("termination", `CONTAINER_${signal}_UNVERIFIED`); }
  };
  try {
    assertArgv(request);
    for (const name of approvedEnvNames) { const value = request.env[name]; if (value && [request.bin, ...request.args].some((arg) => arg.includes(value))) throw new RuntimeFailure("UNSAFE_ARGV"); }
    const requestBytes = Buffer.from(JSON.stringify({ nonce, root: root.root, uid, gid, approvedEnvNames, timeoutMs: bounds.timeoutMs, killGraceMs: bounds.killGraceMs, closeGraceMs: bounds.closeGraceMs, request: { bin: request.bin, args: request.args, cwd: request.cwd, shell: false, env: request.env } }));
    if (requestBytes.length > REQUEST_LIMIT) throw new RuntimeFailure("CONTAINMENT_REQUEST_LIMIT");
    digest = createHash("sha256").update(requestBytes).digest("hex");
    await writeFile(join(root.root, `.harvey-mount-${nonce}`), nonce, { flag: "wx", mode: 0o600 }); markerCreated = true;
    creationAttempted = true; evidence.cleanup = "retained";
    const created = await client.json("POST", `/v${API}/containers/create?name=${name}`, {
      Image: config.imageId, User: "0:0", WorkingDir: "/", Entrypoint: [config.envPath, "-i", config.nodePath, "-e", OBSERVER], Cmd: [],
      Env: imageEnvNames.map((name) => `${name}=`), OpenStdin: true, StdinOnce: true, AttachStdin: true, AttachStdout: true, AttachStderr: true, Tty: false,
      Labels: { [OWNER_LABEL]: nonce }, Healthcheck: { Test: ["NONE"] }, StopSignal: "SIGTERM", NetworkDisabled: true,
      HostConfig: { NetworkMode: "none", PidMode: "", IpcMode: "private", Privileged: false, ReadonlyRootfs: false, AutoRemove: false,
        CapDrop: ["ALL"], CapAdd: ["SETUID", "SETGID"], SecurityOpt: ["no-new-privileges"], PidsLimit: 64, Memory: 512 * 1024 * 1024, NanoCpus: 2_000_000_000,
        RestartPolicy: { Name: "no" }, LogConfig: { Type: "none", Config: {} }, Mounts: [{ Type: "bind", Source: root.root, Target: root.root, ReadOnly: false, BindOptions: { Propagation: "rprivate" } }] },
    }).catch((failure: unknown) => {
      if (failure instanceof RuntimeFailure && [400, 404, 409, 422].includes(failure.httpStatus ?? 0)) { creationAttempted = false; evidence.cleanup = "not-required"; }
      throw failure;
    });
    if (typeof created.Id !== "string" || !CONTAINER_ID.test(created.Id)) throw new RuntimeFailure("CONTAINER_ID_INVALID");
    evidence.containerId = created.Id;
    isolated(await inspect(), config, root.root);
    evidence.isolationVerified = true;
    attachment = await client.attach(evidence.containerId, (stream, bytes) => { try { onData(stream, bytes); } catch { parentFailure = "observer-error"; wake(); } });
    if (bounds.signal?.aborted) { parentFailure = "abort"; throw new RuntimeFailure("ABORTED_BEFORE_START"); }
    assertArgv(request);
    startAttempted = true; evidence.namespace = "unconfirmed"; evidence.targetWork = "unknown"; result.termination.tree = "unconfirmed";
    await client.bytes("POST", `/v${API}/containers/${evidence.containerId}/start`);
    attachment.send(requestBytes);
    bounds.signal?.addEventListener("abort", abort, { once: true });
    if (bounds.signal?.aborted) abort();
    timer = setTimeout(() => { parentFailure ??= "timeout"; wake(); }, bounds.timeoutMs + bounds.killGraceMs + bounds.closeGraceMs + 2_000);
    const finished = await Promise.race([attachment.done.then((complete) => ({ complete })), interrupted.then(() => null)]);
    clearTimeout(timer);
    if (finished !== null) streamComplete = finished.complete;
    if (parentFailure !== null) {
      await kill("SIGTERM");
      const settled = await Promise.race([attachment.done.then((complete) => ({ complete })), delay(bounds.killGraceMs + bounds.closeGraceMs + 100).then(() => null)]);
      if (settled === null) await kill("SIGKILL"); else streamComplete = settled.complete;
    }
  } catch (failure) {
    error(startAttempted ? "observer" : "spawn", failure instanceof RuntimeFailure ? failure.code : "CONTAINMENT_OPERATION_FAILED");
  } finally {
    clearTimeout(timer); bounds.signal?.removeEventListener("abort", abort);
    if (creationAttempted) {
      try {
        let view = await inspect();
        if (!terminal(view)) {
          await kill("SIGTERM");
          await delay(bounds.killGraceMs);
          view = await inspect();
          if (!terminal(view)) { await kill("SIGKILL"); await client.bytes("POST", `/v${API}/containers/${evidence.containerId}/wait?condition=not-running`); view = await inspect(); }
        }
        requireTerminal(view);
        evidence.namespace = startAttempted ? "terminated" : "not-started";
        evidence.terminalObservation = { at: timestamp(), running: false, pid: 0 };
        result.termination.tree = startAttempted ? "absent" : "not-started";
        if (attachment) streamComplete = await Promise.race([attachment.done, delay(bounds.closeGraceMs).then(() => false)]);
        if (startAttempted) {
          try {
            const archived = await client.bytes("GET", `/v${API}/containers/${evidence.containerId}/archive?path=${encodeURIComponent(`/.harvey-readiness-${nonce}/result.json`)}`, undefined, 64 * 1024);
            const observed = metadataFromArchive(archived, digest, uid, gid);
            evidence.metadata = "verified"; evidence.targetIdentity = observed.identity; evidence.observerNodeVersion = observed.nodeVersion;
            evidence.targetWork = observed.pid === null ? "not-started" : "begun";
            result.pid = observed.pid; result.spawnedAt = observed.spawnedAt; result.exit = observed.exit; result.close = observed.close; result.state = observed.state;
            result.errors.push(...observed.errors); result.termination.reason = observed.reason; result.termination.attempts = observed.attempts;
            result.termination.stdioForcedClosed = observed.forced || !streamComplete || !observed.stdoutEnded || !observed.stderrEnded;
          } catch { error("observer", "OBSERVER_METADATA_UNVERIFIED"); result.state = "observer-error"; result.termination.stdioForcedClosed = true; }
        }
        await client.bytes("DELETE", `/v${API}/containers/${evidence.containerId}?force=false&v=false`);
        evidence.cleanup = "removed";
      } catch {
        if (evidence.terminalObservation === null) { evidence.namespace = "unconfirmed"; result.termination.tree = "unconfirmed"; result.state = "termination-unconfirmed"; }
        error("termination", evidence.terminalObservation === null ? "NAMESPACE_TERMINATION_UNCONFIRMED" : "CONTAINER_REMOVAL_UNCONFIRMED");
      }
    }
    attachment?.destroy();
    if (markerCreated && evidence.namespace !== "unconfirmed") await unlink(join(root.root, `.harvey-mount-${nonce}`)).catch(() => undefined);
    const failure = observedFailure();
    if (failure !== null) {
      result.termination.reason ??= failure;
      if (result.state !== "termination-unconfirmed") result.state = failure === "abort" ? "aborted" : failure === "timeout" ? "timed-out" : "observer-error";
      if (failure === "observer-error") error("observer", "OBSERVER_FAILED");
    }
    if (evidence.namespace === "unconfirmed") result.termination.stdioForcedClosed = true;
  }
}
