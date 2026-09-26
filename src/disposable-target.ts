import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { lstat, mkdir, mkdtemp, open, readdir, readlink, realpath, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep, win32 } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const DEFAULT_LIMITS = { maxEntries: 250_000, maxBytes: 2 * 1024 ** 3, maxDepth: 100 } as const;
const EXCLUDED_NAMES = new Set([
  ".git", ".hg", ".svn", ".bzr", "node_modules", ".pnpm-store", ".next", ".nuxt",
  ".output", ".svelte-kit", ".astro", ".turbo", ".cache", ".parcel-cache", ".vite",
  "dist", "build", "coverage", ".nyc_output", ".vercel", ".netlify", ".yarn-cache",
  ".pnp.cjs", ".pnp.loader.mjs", ".pnp.data.json", ".npmrc", ".yarnrc", ".yarnrc.yml",
]);

export interface DisposableTargetLimits {
  maxEntries?: number;
  maxBytes?: number;
  maxDepth?: number;
}

type Limits = Required<DisposableTargetLimits>;

/** Source entries, including excluded copy artifacts, are hashed; Git internals use HEAD/status evidence. */
export interface SourceSentinelV1 {
  schemaVersion: 1;
  sourceRoot: string;
  contentSha256: string;
  entries: number;
  bytes: number;
  git: { status: "present"; head: string | null; statusSha256: string } | { status: "absent" };
}

export type SourcePreservationReceipt =
  | { status: "passed"; before: SourceSentinelV1; after: SourceSentinelV1 }
  | { status: "failed"; before: SourceSentinelV1; after?: SourceSentinelV1; reasonCode: "source-changed" | "source-unreadable"; reason: string; falsifier: string };

export type DisposableCleanupReceipt =
  | { status: "not-required"; root: null; reason: string }
  | { status: "failed"; root: string | null; reasonCode: "unbound-temporary-root" | "unrecognized-target"; reason: string; falsifier: string }
  | {
      status: "passed" | "failed";
      root: string;
      startedAt: string;
      endedAt: string;
      durationMs: number;
      removal: { status: "removed" } | { status: "failed"; reasonCode: string; reason: string; falsifier: string };
      source: SourcePreservationReceipt;
    };

export interface DisposableTarget {
  readonly root: string;
  readonly targetRoot: string;
  readonly sourceRoot: string;
  readonly sourceBefore: SourceSentinelV1;
  readonly copy: { readonly files: number; readonly bytes: number; readonly excluded: readonly string[] };
}

export type DisposableTargetCreation =
  | { status: "ready"; target: DisposableTarget }
  | { status: "not-assessed"; reasonCode: string; reason: string; falsifier: string; cleanup: DisposableCleanupReceipt };

export type RunRootVerification =
  | { status: "verified"; root: string; cwd: string }
  | { status: "not-assessed"; reasonCode: string; reason: string; falsifier: string };

interface TargetState {
  rootIdentity: Stats;
  targetIdentity?: Stats;
  limits: Limits;
  cleanup?: Promise<DisposableCleanupReceipt>;
}

const targets = new WeakMap<DisposableTarget, TargetState>();

class BoundaryError extends Error {
  constructor(readonly code: string, message: string) { super(message); }
}

function limitsFor(value: DisposableTargetLimits = {}): Limits {
  const limits = { ...DEFAULT_LIMITS, ...value };
  for (const limit of Object.values(limits)) {
    if (!Number.isSafeInteger(limit) || limit <= 0) throw new BoundaryError("invalid-limits", "Disposable target limits must be positive safe integers.");
  }
  return limits;
}

function within(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`));
}

function sameIdentity(a: Stats, b: Stats): boolean { return a.dev === b.dev && a.ino === b.ino; }
function unchanged(a: Stats, b: Stats): boolean {
  return sameIdentity(a, b) && a.mode === b.mode && a.size === b.size && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs;
}

function canonicalRelative(path: string): boolean {
  return path === "." || (path !== "" && !path.includes("\0") && !path.includes("\\") && !isAbsolute(path) && !win32.isAbsolute(path)
    && path.split("/").every((part) => part !== "" && part !== "." && part !== ".."));
}

function excluded(path: string): boolean {
  const parts = path.split("/");
  return parts.some((part) => EXCLUDED_NAMES.has(part) || part === ".env" || part.startsWith(".env."))
    || parts.some((part, index) => part === ".yarn" && ["cache", "unplugged", "install-state.gz", "build-state.yml"].includes(parts[index + 1] ?? ""));
}

function refusal(error: unknown): { reasonCode: string; reason: string; falsifier: string } {
  const boundary = error instanceof BoundaryError;
  return {
    reasonCode: boundary ? error.code : "filesystem-unavailable",
    reason: boundary ? error.message : "The filesystem operation could not be verified; no target command is authorized.",
    falsifier: "Provide an unchanged readable source and an independent writable temporary directory with only confined regular files, directories, and links, then retry.",
  };
}

async function assertDirectory(path: string, root: string, identity?: Stats): Promise<Stats> {
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink() || !within(root, await realpath(path)) || (identity && !sameIdentity(info, identity))) {
    throw new BoundaryError("directory-escape", "A required directory was replaced or resolves outside its admitted root.");
  }
  return info;
}

async function gitSentinel(sourceRoot: string): Promise<SourceSentinelV1["git"]> {
  // Looking for metadata first distinguishes a non-Git source from a failed Git observation.
  let dir = sourceRoot;
  let hasGit = false;
  for (;;) {
    try { await lstat(join(dir, ".git")); hasGit = true; break; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  if (!hasGit) return { status: "absent" };
  const args = ["--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.hooksPath=/dev/null", "-C", sourceRoot];
  const environment: NodeJS.ProcessEnv = { PATH: "/usr/bin:/bin:/usr/local/bin", GIT_OPTIONAL_LOCKS: "0", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0", LC_ALL: "C" };
  const options = {
    env: environment,
    timeout: 10_000,
    maxBuffer: 4 * 1024 ** 2,
    encoding: "utf8" as const,
  };
  const top = await execFileAsync("git", [...args, "rev-parse", "--show-toplevel"], options);
  if (!within(await realpath(top.stdout.trim()), sourceRoot)) throw new BoundaryError("git-worktree-escape", "Git metadata redirects the source observation to a different worktree.");
  const filterKeys = await execFileAsync("git", [...args, "config", "--null", "--name-only", "--get-regexp", "^filter\\..*\\.(clean|smudge|process|required)$"], options)
    .then((result) => result.stdout.split("\0").filter(Boolean))
    .catch((error: unknown) => { if ((error as { code?: unknown }).code === 1) return []; throw error; });
  // Status can invoke a clean/process filter from untrusted .git/config. Disable every discovered
  // driver, including included configuration, before asking Git to inspect working-tree contents.
  for (const [index, key] of filterKeys.entries()) {
    if (!/^filter\..*\.(?:clean|smudge|process|required)$/i.test(key)) throw new BoundaryError("git-filter-config", "Git filter configuration could not be safely neutralized.");
    // Driver names come from target configuration. Keep those opaque keys in
    // the private environment rather than exposing them in process argv.
    environment[`GIT_CONFIG_KEY_${index}`] = key;
    environment[`GIT_CONFIG_VALUE_${index}`] = key.toLowerCase().endsWith(".required") ? "false" : "";
  }
  environment.GIT_CONFIG_COUNT = String(filterKeys.length);
  const status = await execFileAsync("git", [...args, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=all", "--", "."], options);
  const head = await execFileAsync("git", [...args, "rev-parse", "--verify", "--quiet", "HEAD"], options)
    .then((result) => result.stdout.trim())
    .catch((error: unknown) => {
      if ((error as { code?: unknown }).code === 1) return null;
      throw error;
    });
  return { status: "present", head, statusSha256: createHash("sha256").update(status.stdout).digest("hex") };
}

/** Does not follow source symlinks or execute target code. Git observation disables optional writes and fsmonitor. */
export async function captureSourceSentinel(source: string, requestedLimits: DisposableTargetLimits = {}): Promise<SourceSentinelV1> {
  const limits = limitsFor(requestedLimits);
  const sourceRoot = await realpath(source);
  await assertDirectory(sourceRoot, sourceRoot);
  const hash = createHash("sha256");
  let entries = 0;
  let bytes = 0;
  const visit = async (path: string, rel: string, depth: number): Promise<void> => {
    if (++entries > limits.maxEntries || depth > limits.maxDepth) throw new BoundaryError("source-limit", "Source sentinel entry/depth limit was exceeded.");
    const info = await lstat(path);
    hash.update(JSON.stringify([rel, info.mode]));
    if (info.isSymbolicLink()) {
      hash.update(JSON.stringify(["symlink", await readlink(path)]));
    } else if (info.isDirectory()) {
      await assertDirectory(path, sourceRoot, info);
      // Git status and HEAD cover repository state without hashing mutable Git caches/locks.
      if (rel.split("/").at(-1) !== ".git") {
        for (const name of (await readdir(path)).sort()) await visit(join(path, name), rel === "." ? name : `${rel}/${name}`, depth + 1);
      }
    } else if (info.isFile()) {
      bytes += info.size;
      if (bytes > limits.maxBytes) throw new BoundaryError("source-limit", "Source sentinel byte limit was exceeded.");
      if (!within(sourceRoot, await realpath(path))) throw new BoundaryError("source-escape", "A source file resolves outside the source root.");
      const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        if (!unchanged(info, await file.stat())) throw new BoundaryError("source-changed", "A source file changed while the sentinel was being read.");
        const digest = createHash("sha256");
        for await (const chunk of file.createReadStream({ autoClose: false })) digest.update(chunk);
        hash.update(JSON.stringify(["file", info.size, digest.digest("hex")]));
        if (!unchanged(info, await file.stat())) throw new BoundaryError("source-changed", "A source file changed while the sentinel was being read.");
      } finally { await file.close(); }
    } else {
      throw new BoundaryError("unsupported-source-entry", "The source contains a device, socket, or other unsupported special file.");
    }
    if (!unchanged(info, await lstat(path))) throw new BoundaryError("source-changed", "A source entry changed while the sentinel was being read.");
  };
  await visit(sourceRoot, ".", 0);
  return Object.freeze({ schemaVersion: 1, sourceRoot, contentSha256: hash.digest("hex"), entries, bytes, git: Object.freeze(await gitSentinel(sourceRoot)) });
}

function sameSentinel(a: SourceSentinelV1, b: SourceSentinelV1): boolean {
  return a.sourceRoot === b.sourceRoot && a.contentSha256 === b.contentSha256 && a.entries === b.entries && a.bytes === b.bytes && JSON.stringify(a.git) === JSON.stringify(b.git);
}

async function preservation(target: DisposableTarget, limits: Limits): Promise<SourcePreservationReceipt> {
  try {
    const after = await captureSourceSentinel(target.sourceRoot, limits);
    if (sameSentinel(target.sourceBefore, after)) return { status: "passed", before: target.sourceBefore, after };
    return { status: "failed", before: target.sourceBefore, after, reasonCode: "source-changed", reason: "The original target content or Git state changed during readiness execution.", falsifier: "Repeat with a disposable-only writer and reproduce identical before/after source content and Git sentinels." };
  } catch {
    return { status: "failed", before: target.sourceBefore, reasonCode: "source-unreadable", reason: "The original target could not be re-observed after readiness execution.", falsifier: "Restore readable original source state and reproduce identical before/after sentinels." };
  }
}

export async function createDisposableTarget(source: string, options: { tempParent?: string; limits?: DisposableTargetLimits } = {}): Promise<DisposableTargetCreation> {
  let target: DisposableTarget | undefined;
  let allocatedRoot: string | undefined;
  try {
    const limits = limitsFor(options.limits);
    const before = await captureSourceSentinel(source, limits);
    const parent = await realpath(options.tempParent ?? tmpdir());
    await assertDirectory(parent, parent);
    if (within(before.sourceRoot, parent)) throw new BoundaryError("temp-inside-source", "The disposable temporary parent is inside the original target.");
    allocatedRoot = await mkdtemp(join(parent, "harvey-readiness-"));
    const root = await realpath(allocatedRoot);
    if (within(before.sourceRoot, root) || within(root, before.sourceRoot)) throw new BoundaryError("source-run-overlap", "The source and disposable roots overlap.");
    const copy = { files: 0, bytes: 0, excluded: [] as string[] };
    target = Object.freeze({ root, targetRoot: join(root, "target"), sourceRoot: before.sourceRoot, sourceBefore: before, copy });
    const rootIdentity = await lstat(root);
    const state: TargetState = { rootIdentity, limits };
    targets.set(target, state);
    await mkdir(target.targetRoot, { mode: 0o700 });
    state.targetIdentity = await lstat(target.targetRoot);
    for (const name of ["home", "tmp", "cache"]) await mkdir(join(root, name), { mode: 0o700 });
    let copiedEntries = 0;
    const copyEntry = async (from: string, to: string, rel: string): Promise<void> => {
      if (++copiedEntries > limits.maxEntries || rel.split("/").length > limits.maxDepth) throw new BoundaryError("copy-limit", "Disposable copy entry/depth bound was exceeded.");
      if (excluded(rel)) { copy.excluded.push(rel); return; }
      const info = await lstat(from);
      if (info.isSymbolicLink()) {
        const resolved = await realpath(from);
        const linkRelative = relative(before.sourceRoot, resolved).split(sep).join("/");
        if (!within(before.sourceRoot, resolved) || excluded(linkRelative)) {
          throw new BoundaryError("source-link-escape", "A retained source link escapes the source or points to an excluded dependency/build artifact.");
        }
        // Rebase absolute internal links into the copy, removing their original source path.
        await symlink(relative(dirname(to), join(target!.targetRoot, linkRelative)) || ".", to);
      } else if (info.isDirectory()) {
        await assertDirectory(from, before.sourceRoot, info);
        await mkdir(to, { mode: 0o700 });
        for (const name of (await readdir(from)).sort()) await copyEntry(join(from, name), join(to, name), rel === "." ? name : `${rel}/${name}`);
      } else if (info.isFile()) {
        if (!within(before.sourceRoot, await realpath(from))) throw new BoundaryError("source-escape", "A copied source file resolves outside the original root.");
        copy.bytes += info.size;
        if (copy.bytes > limits.maxBytes) throw new BoundaryError("copy-limit", "Disposable copy byte bound was exceeded.");
        const input = await open(from, constants.O_RDONLY | constants.O_NOFOLLOW);
        try {
          if (!unchanged(info, await input.stat())) throw new BoundaryError("source-changed", "A source file changed before copying.");
          const output = await open(to, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, info.mode & 0o777);
          try {
            const buffer = Buffer.alloc(64 * 1024);
            let copied = 0;
            while (copied < info.size) {
              const { bytesRead } = await input.read(buffer, 0, Math.min(buffer.length, info.size - copied), copied);
              if (bytesRead === 0) throw new BoundaryError("source-changed", "A source file was truncated while copying.");
              let written = 0;
              while (written < bytesRead) written += (await output.write(buffer, written, bytesRead - written, copied + written)).bytesWritten;
              copied += bytesRead;
            }
            if (!unchanged(info, await input.stat())) throw new BoundaryError("source-changed", "A source file changed while copying.");
          } finally { await output.close(); }
        } finally { await input.close(); }
        copy.files++;
      } else throw new BoundaryError("unsupported-source-entry", "Only regular files, directories, and confined links can enter the disposable copy.");
      if (!unchanged(info, await lstat(from))) throw new BoundaryError("source-changed", "Source content changed while the disposable copy was created.");
    };
    for (const name of (await readdir(before.sourceRoot)).sort()) await copyEntry(join(before.sourceRoot, name), join(target.targetRoot, name), name);
    const sourceCheck = await preservation(target, limits);
    if (sourceCheck.status !== "passed") throw new BoundaryError("source-changed", "The original source changed while the disposable copy was created.");
    const runCheck = await verifyRunRoot(target);
    if (runCheck.status !== "verified") throw new BoundaryError(runCheck.reasonCode, runCheck.reason);
    Object.freeze(copy.excluded);
    Object.freeze(copy);
    return { status: "ready", target };
  } catch (error) {
    let cleanup: DisposableCleanupReceipt;
    if (target && targets.has(target)) cleanup = await cleanupDisposableTarget(target);
    else if (allocatedRoot) {
      // An allocation whose identity was not retained is never guessed safe to remove.
      cleanup = { status: "failed", root: allocatedRoot, reasonCode: "unbound-temporary-root", reason: "The allocated temporary root could not be bound safely for removal.", falsifier: "Verify and remove the retained allocation manually, then use a stable temporary parent." };
      return { status: "not-assessed", reasonCode: "unbound-temporary-root", reason: "Temporary allocation identity could not be verified; manual cleanup may be required.", falsifier: "Provide a stable realpathed temporary parent and retry.", cleanup };
    } else cleanup = { status: "not-required", root: null, reason: "Admission failed before a disposable root was allocated." };
    return { status: "not-assessed", ...refusal(error), cleanup };
  }
}

/** Recheck immediately before every spawn, including links produced by an admitted install. */
export async function verifyRunRoot(target: DisposableTarget, relativeCwd = "."): Promise<RunRootVerification> {
  try {
    const state = targets.get(target);
    if (!state || state.cleanup) throw new BoundaryError("inactive-target", "The disposable handle is unknown or cleanup has already begun.");
    if (!canonicalRelative(relativeCwd)) throw new BoundaryError("cwd-escape", "The stage cwd must be a canonical target-relative directory.");
    await assertDirectory(target.root, target.root, state.rootIdentity);
    if (await realpath(target.root) !== target.root) throw new BoundaryError("root-replaced", "The disposable root no longer resolves to its recorded path.");
    await assertDirectory(target.targetRoot, target.root, state.targetIdentity);
    if (await realpath(target.sourceRoot) !== target.sourceRoot || within(target.root, target.sourceRoot) || within(target.sourceRoot, target.root)) {
      throw new BoundaryError("source-run-overlap", "The original source root changed or overlaps the disposable root.");
    }
    let entries = 0;
    const inodes = new Map<string, { seen: number; links: number }>();
    const visit = async (path: string, depth: number): Promise<void> => {
      if (++entries > state.limits.maxEntries || depth > state.limits.maxDepth) throw new BoundaryError("run-root-limit", "Disposable root verification exceeded its entry/depth bound.");
      const info = await lstat(path);
      if (info.isSymbolicLink()) {
        if (!within(target.root, await realpath(path))) throw new BoundaryError("run-link-escape", "A disposable link resolves outside the disposable root.");
      } else if (info.isDirectory()) {
        await assertDirectory(path, target.root, info);
        for (const name of await readdir(path)) await visit(join(path, name), depth + 1);
      } else if (info.isFile()) {
        const key = `${info.dev}:${info.ino}`;
        const row = inodes.get(key) ?? { seen: 0, links: info.nlink };
        row.seen++;
        inodes.set(key, row);
      } else throw new BoundaryError("unsupported-run-entry", "A disposable root contains an unsupported special file.");
    };
    await visit(target.root, 0);
    if ([...inodes.values()].some((row) => row.seen !== row.links)) throw new BoundaryError("run-hardlink-escape", "A disposable file has a hard link outside the disposable root.");
    const cwd = await realpath(resolve(target.targetRoot, relativeCwd));
    if (!within(target.targetRoot, cwd) || !(await stat(cwd)).isDirectory()) throw new BoundaryError("cwd-escape", "The stage cwd resolves outside the disposable target tree.");
    return { status: "verified", root: target.root, cwd };
  } catch (error) { return { status: "not-assessed", ...refusal(error) }; }
}

/** Unresolved ownership prevents deletion even if a later caller asks for unconditional cleanup. */
export async function retainDisposableTarget(target: DisposableTarget, reason: { reasonCode: string; reason: string; falsifier: string }): Promise<DisposableCleanupReceipt> {
  const state = targets.get(target);
  if (!state) return { status: "failed", root: null, reasonCode: "unrecognized-target", reason: "Retention refused an unrecognized disposable target handle.", falsifier: "Retain only the authentic target handle created by this run." };
  if (state.cleanup) return state.cleanup;
  state.cleanup = (async () => {
    const startedAt = new Date().toISOString();
    const start = performance.now();
    const source = await preservation(target, state.limits);
    return { status: "failed" as const, root: target.root, startedAt, endedAt: new Date().toISOString(), durationMs: Math.max(0, performance.now() - start), removal: { status: "failed" as const, ...reason }, source };
  })();
  return state.cleanup;
}

/** Delete only after every owned workload has a terminal observation. */
export function cleanupDisposableTarget(target: DisposableTarget): Promise<DisposableCleanupReceipt> {
  const state = targets.get(target);
  if (!state) return Promise.resolve({ status: "failed", root: null, reasonCode: "unrecognized-target", reason: "Cleanup refused an unrecognized disposable target handle; no path was removed.", falsifier: "Pass the authentic handle returned by createDisposableTarget to cleanup." });
  if (state.cleanup) return state.cleanup;
  state.cleanup = (async (): Promise<DisposableCleanupReceipt> => {
    const start = performance.now();
    const startedAt = new Date().toISOString();
    let removal: Extract<DisposableCleanupReceipt, { startedAt: string }>["removal"];
    try {
      await assertDirectory(target.root, target.root, state.rootIdentity);
      if (await realpath(target.root) !== target.root || within(target.sourceRoot, target.root) || within(target.root, target.sourceRoot)) {
        throw new BoundaryError("cleanup-root-replaced", "Cleanup root identity or source confinement changed.");
      }
      await rm(target.root, { recursive: true, force: false, maxRetries: 0 });
      try { await lstat(target.root); throw new BoundaryError("cleanup-incomplete", "The disposable root still exists after cleanup."); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
      removal = { status: "removed" };
    } catch (error) { removal = { status: "failed", ...refusal(error) }; }
    const source = await preservation(target, state.limits);
    return { status: removal.status === "removed" && source.status === "passed" ? "passed" : "failed", root: target.root, startedAt, endedAt: new Date().toISOString(), durationMs: Math.max(0, performance.now() - start), removal, source };
  })();
  return state.cleanup;
}
