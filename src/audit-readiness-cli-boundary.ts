import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { validateReadinessEnvironmentNames } from "./audit-readiness-authority.js";

export interface CapturedReadinessAuthorization {
  value?: unknown;
  parsed: boolean;
  namesValidated: boolean;
  redactionNames: string[];
  redactionValues: string[];
}

/** Read once; validate the whole name set before consulting any associated environment value. */
export function captureReadinessAuthorization(
  path: string | undefined,
  environment: Readonly<Record<string, string | undefined>>,
): CapturedReadinessAuthorization {
  if (!path) return { parsed: true, namesValidated: true, redactionNames: [], redactionValues: [] };
  let value: unknown;
  try { value = JSON.parse(readFileSync(path, "utf8")); }
  catch { return { parsed: false, namesValidated: false, redactionNames: [], redactionValues: [] }; }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { value, parsed: true, namesValidated: false, redactionNames: [], redactionValues: [] };
  }
  const candidate = (value as Record<string, unknown>).approvedEnvNames;
  if (!Array.isArray(candidate)) return { value, parsed: true, namesValidated: false, redactionNames: [], redactionValues: [] };
  let redactionNames: string[];
  try { redactionNames = validateReadinessEnvironmentNames(candidate); }
  catch { return { value, parsed: true, namesValidated: false, redactionNames: [], redactionValues: [] }; }
  const redactionValues = redactionNames.flatMap((name) => {
    const value = Object.hasOwn(environment, name) ? environment[name] : undefined;
    return typeof value === "string" && value !== "" && !value.includes("\0") ? [value] : [];
  });
  return { value, parsed: true, namesValidated: true, redactionNames, redactionValues: [...new Set(redactionValues)].sort((a, b) => b.length - a.length) };
}

export function redactCliText(text: string, values: readonly string[]): string {
  let redacted = text;
  for (const value of values) if (value) redacted = redacted.split(value).join("[REDACTED]");
  return redacted;
}

/** The CLI is the public terminal boundary; downstream findings/artifacts remain byte-for-byte unchanged. */
export function installCliConsoleRedaction(values: readonly string[]): void {
  if (values.length === 0) return;
  for (const method of ["log", "info", "warn", "error"] as const) {
    const original = console[method].bind(console);
    console[method] = ((...args: unknown[]) => original(...args.map((arg) => {
      if (typeof arg === "string") return redactCliText(arg, values);
      if (arg instanceof Error) return redactCliText(arg.message, values);
      return arg;
    }))) as typeof console[typeof method];
  }
}

export interface RequestedArtifactDestination { flag: string; path: string }

function physicalPath(path: string): string {
  const absolute = resolve(path);
  if (existsSync(absolute)) return realpathSync.native(absolute);
  let parent = dirname(absolute);
  while (!existsSync(parent)) {
    const next = dirname(parent);
    if (next === parent) return absolute;
    parent = next;
  }
  return join(realpathSync.native(parent), relative(parent, absolute));
}

/** Reject lexical, symlink and existing hard-link aliases before any requested artifact is written. */
export function assertDistinctArtifactDestinations(destinations: readonly RequestedArtifactDestination[]): void {
  const identities = destinations.map((destination) => {
    const absolute = resolve(destination.path);
    const stat = existsSync(absolute) ? lstatSync(realpathSync.native(absolute)) : undefined;
    return {
      ...destination,
      absolute,
      physical: physicalPath(absolute),
      inode: stat ? `${stat.dev}:${stat.ino}` : undefined,
    };
  });
  for (let i = 0; i < identities.length; i += 1) for (let j = i + 1; j < identities.length; j += 1) {
    const left = identities[i]!;
    const right = identities[j]!;
    if (left.absolute === right.absolute || left.physical === right.physical || (left.inode !== undefined && left.inode === right.inode)) {
      throw new Error(`Requested artifact destinations alias: ${left.flag} and ${right.flag}.`);
    }
  }
}

export interface CurrentArtifactWrite {
  bytes: number;
  sha256: string;
}

export function writeCurrentArtifact(
  path: string,
  contents: string | Buffer,
  writes: Map<string, CurrentArtifactWrite>,
): void {
  const expected = Buffer.isBuffer(contents) ? contents : Buffer.from(contents);
  writeFileSync(path, expected);
  const actual = readFileSync(path);
  const expectedSha256 = createHash("sha256").update(expected).digest("hex");
  const actualSha256 = createHash("sha256").update(actual).digest("hex");
  if (actual.length !== expected.length || actualSha256 !== expectedSha256) throw new Error("Requested artifact verification failed.");
  writes.set(resolve(path), { bytes: actual.length, sha256: actualSha256 });
}

export function isCurrentArtifact(
  path: string,
  writes: ReadonlyMap<string, CurrentArtifactWrite>,
): boolean {
  const receipt = writes.get(resolve(path));
  if (!receipt) return false;
  try {
    const bytes = readFileSync(path);
    return bytes.length === receipt.bytes && createHash("sha256").update(bytes).digest("hex") === receipt.sha256;
  } catch { return false; }
}
