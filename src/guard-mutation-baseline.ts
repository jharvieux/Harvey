import { createHash } from "node:crypto";
import { posix } from "node:path";
import { GUARD_SET } from "./guard-mutation-census.js";

type Location = { start: { line: number; column: number }; end: { line: number; column: number } };
type Status = "Killed" | "Timeout" | "Survived" | "NoCoverage" | "CompileError" | "RuntimeError" | "Ignored" | "Pending";
// attempted counts reported mutants; excluded is a guard indicator. A failed exclusion probe's
// generated population is recorded separately: inventing terminal statuses for it would fake data.
type Population = { attempted: number; killed: number; survived: number; noCoverage: number; unscored: number; excluded: number };
type Mutant = { id: string; mutator: string; location: Location; original: string; replacement: string; status: Status };
type ExclusionCheck = {
  file: string;
  outcome: "blocked" | "measurable" | "uncheckable";
  attempted: number;
  exitCode: number;
  command: string;
  outputSha256: string;
  detail: string;
};

export interface GuardMutationReceipt {
  schemaVersion: 1;
  startedAt: string;
  finishedAt: string;
  sourceCommit: string;
  reportSha256: string;
  configSha256: string;
  sourceSha256: Record<string, string>;
  toolchain: {
    node: string;
    packageManager: string;
    packageJsonSha256: string;
    lockfileSha256: string;
    packages: Record<string, { version: string; packageJsonSha256: string }>;
  };
  exclusionChecks: ExclusionCheck[];
}

type Guard = {
  file: string;
  sourceSha256: string;
  state: "measured" | "unexercised" | "unscored" | "excluded" | "missing";
  population: Population;
  mutants: Mutant[];
  exclusion?: ExclusionCheck;
};

export interface NormalizedGuardCensus {
  schemaVersion: 1;
  identityVersion: "file-location-mutation-v1";
  receipt: GuardMutationReceipt;
  guards: Guard[];
}

export interface GuardMutationReview {
  key: string;
  owner: string;
  reviewedAt: string;
  reviewedBy: string;
  sourceCommit: string;
  sourceSha256: string;
  reportSha256: string;
  reason?: string;
  expiresAt?: string;
  remediationIssue?: string;
}

export interface GuardMutationBaseline {
  schemaVersion: 1;
  census: NormalizedGuardCensus;
  reviews: GuardMutationReview[];
}

const STATUSES = new Set<Status>(["Killed", "Timeout", "Survived", "NoCoverage", "CompileError", "RuntimeError", "Ignored", "Pending"]);
const PACKAGES = ["@stryker-mutator/core", "@stryker-mutator/vitest-runner", "vitest", "typescript"];
const HASH = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const own = (value: object, key: string): boolean => Object.hasOwn(value, key);

export const guardMutationDigest = (value: string | Buffer): string => createHash("sha256").update(value).digest("hex");

function demand(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function record(value: unknown, label: string): Record<string, unknown> {
  demand(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  return value as Record<string, unknown>;
}

function text(value: unknown, label: string): string {
  demand(typeof value === "string" && value.trim().length > 0, `${label} must be nonblank`);
  return value;
}

function integer(value: unknown, label: string): number {
  demand(typeof value === "number" && Number.isSafeInteger(value) && value >= 0, `${label} must be a nonnegative integer`);
  return value;
}

function hash(value: unknown, label: string): string {
  const result = text(value, label);
  demand(HASH.test(result), `${label} must be a SHA-256 digest`);
  return result;
}

function commit(value: unknown, label: string): string {
  const result = text(value, label);
  demand(COMMIT.test(result), `${label} must be a full Git commit`);
  return result;
}

function date(value: unknown, label: string): string {
  const result = text(value, label);
  demand(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(result) && Number.isFinite(Date.parse(result)), `${label} must be a UTC timestamp`);
  return result;
}

function list(value: unknown, label: string): unknown[] {
  demand(Array.isArray(value), `${label} must be an array`);
  return value;
}

function guardPath(value: unknown): string {
  const path = text(value, "guard path").replaceAll("\\", "/");
  demand(!path.startsWith("/") && !path.split("/").includes(".."), `unsafe guard path: ${path}`);
  const normalized = posix.normalize(path);
  demand((GUARD_SET as readonly string[]).includes(normalized), `undeclared guard: ${path}`);
  return normalized;
}

function unique<T>(values: T[], key: (value: T) => string, label: string): T[] {
  const keys = values.map(key);
  demand(new Set(keys).size === keys.length, `duplicate ${label}`);
  return values;
}

function exclusionCheck(value: unknown): ExclusionCheck {
  const x = record(value, "exclusion check");
  demand(x.outcome === "blocked" || x.outcome === "measurable" || x.outcome === "uncheckable", "unknown exclusion outcome");
  const result: ExclusionCheck = {
    file: guardPath(x.file), outcome: x.outcome, attempted: integer(x.attempted, "exclusion attempted"),
    exitCode: integer(x.exitCode, "exclusion exitCode"), command: text(x.command, "exclusion command"),
    outputSha256: hash(x.outputSha256, "exclusion outputSha256"), detail: text(x.detail, "exclusion detail"),
  };
  if (result.outcome === "blocked") demand(result.attempted > 0 && result.exitCode !== 0 && result.exitCode !== 127, `${result.file}: an exclusion needs an actual failed instrumentation attempt`);
  if (result.outcome === "measurable") demand(result.attempted > 0 && result.exitCode === 0, `${result.file}: measurable exclusion probe must exit 0 after instrumentation`);
  return result;
}

function parseGuardMutationReceipt(value: unknown, expectedGuards: readonly string[] = GUARD_SET): GuardMutationReceipt {
  const x = record(value, "capture receipt");
  demand(x.schemaVersion === 1, "unsupported capture receipt schemaVersion");
  const t = record(x.toolchain, "toolchain");
  const p = record(t.packages, "toolchain packages");
  demand(Object.keys(p).sort().join() === [...PACKAGES].sort().join(), "capture must identify every required package exactly");
  const packages = Object.fromEntries(PACKAGES.map((name) => {
    const pkg = record(p[name], name);
    const version = text(pkg.version, `${name} version`);
    demand(/^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(version), `${name} needs an exact version`);
    return [name, { version, packageJsonSha256: hash(pkg.packageJsonSha256, `${name} packageJsonSha256`) }];
  }));
  const sources = record(x.sourceSha256, "sourceSha256");
  demand(Object.keys(sources).sort().join() === [...expectedGuards].sort().join(), "capture source identities must include every declared guard exactly");
  const sourceSha256 = Object.fromEntries(expectedGuards.map((file) => [file, hash(sources[file], `${file} sourceSha256`)]));
  const node = text(t.node, "Node identity");
  demand(/^v\d+\.\d+\.\d+$/.test(node), "Node identity needs an exact version");
  const packageManager = text(t.packageManager, "package manager identity");
  demand(/^pnpm@\d+\.\d+\.\d+$/.test(packageManager), "package manager identity needs an exact version");
  const startedAt = date(x.startedAt, "capture startedAt");
  const finishedAt = date(x.finishedAt, "capture finishedAt");
  demand(Date.parse(startedAt) <= Date.parse(finishedAt), "capture finishes before it starts");
  return {
    schemaVersion: 1, startedAt, finishedAt, sourceCommit: commit(x.sourceCommit, "capture sourceCommit"),
    reportSha256: hash(x.reportSha256, "capture reportSha256"), configSha256: hash(x.configSha256, "capture configSha256"), sourceSha256,
    toolchain: { node, packageManager, packages, packageJsonSha256: hash(t.packageJsonSha256, "packageJsonSha256"), lockfileSha256: hash(t.lockfileSha256, "lockfileSha256") },
    exclusionChecks: unique(list(x.exclusionChecks, "exclusionChecks").map(exclusionCheck), (entry) => entry.file, "exclusion check").sort((a, b) => a.file.localeCompare(b.file)),
  };
}

function location(value: unknown): Location {
  const x = record(value, "mutant location");
  const point = (value: unknown): Location["start"] => {
    const p = record(value, "mutant position");
    const line = integer(p.line, "line");
    const column = integer(p.column, "column");
    demand(line > 0 && column > 0, "Stryker positions are one-based");
    return { line, column };
  };
  const start = point(x.start); const end = point(x.end);
  demand(end.line > start.line || (end.line === start.line && end.column > start.column), "empty or inverted mutant location");
  return { start, end };
}

function originalAt(source: string, loc: Location): string {
  const lines = source.split("\n");
  const offset = (p: Location["start"]): number => {
    demand(p.line <= lines.length && p.column <= lines[p.line - 1]!.length + 1, "mutant location is outside captured source");
    return lines.slice(0, p.line - 1).reduce((sum, line) => sum + line.length + 1, 0) + p.column - 1;
  };
  return source.slice(offset(loc.start), offset(loc.end));
}

function mutantId(file: string, mutant: Omit<Mutant, "id" | "status">): string {
  // Stryker ids and test ids depend on enumeration/sharding. Source positions and mutation bytes
  // are the identity; a source edit that moves them deliberately requires a reviewed delta.
  return guardMutationDigest(JSON.stringify([file, mutant.location, mutant.mutator, mutant.original, mutant.replacement]));
}

function readMutant(value: unknown, file: string, source?: string): Mutant {
  const x = record(value, "mutant");
  const loc = location(x.location);
  const mutator = text(source === undefined ? x.mutator : x.mutatorName, "mutator");
  demand(typeof x.replacement === "string", "mutant replacement is required for stable identity");
  demand(typeof x.status === "string" && STATUSES.has(x.status as Status), `unknown mutant status: ${String(x.status)}`);
  const original = source === undefined ? text(x.original, "mutant original") : originalAt(source, loc);
  const fields = { mutator, location: loc, original, replacement: x.replacement };
  const id = mutantId(file, fields);
  if (source === undefined) demand(x.id === id, `mutant identity mismatch in ${file}`);
  return { id, ...fields, status: x.status as Status };
}

function population(mutants: Mutant[], excluded = false): Population {
  return {
    attempted: mutants.length,
    killed: mutants.filter((m) => m.status === "Killed" || m.status === "Timeout").length,
    survived: mutants.filter((m) => m.status === "Survived").length,
    noCoverage: mutants.filter((m) => m.status === "NoCoverage").length,
    unscored: mutants.filter((m) => !["Killed", "Timeout", "Survived", "NoCoverage"].includes(m.status)).length,
    excluded: Number(excluded),
  };
}

function measuredState(p: Population): Guard["state"] {
  if (p.attempted === 0) return "unexercised";
  if (p.killed + p.survived + p.noCoverage === 0) return "unscored";
  return p.killed + p.survived === 0 ? "unexercised" : "measured";
}

export function normalizeGuardMutationCensus(reportValue: unknown, receiptValue: unknown, reportSha256: string): NormalizedGuardCensus {
  const receipt = parseGuardMutationReceipt(receiptValue);
  demand(receipt.reportSha256 === reportSha256, "raw report digest does not match its capture receipt");
  const report = record(reportValue, "Stryker report");
  demand(report.schemaVersion === "1.0", "unsupported Stryker report schemaVersion");
  const framework = record(report.framework, "Stryker framework identity");
  demand(framework.name === "StrykerJS" && framework.version === receipt.toolchain.packages["@stryker-mutator/core"]!.version, "Stryker report and capture toolchain disagree");
  const files = record(report.files, "Stryker files");
  const entries = unique(Object.entries(files).map(([file, value]) => ({ file: guardPath(file), value: record(value, file) })), (entry) => entry.file, "normalized guard path");
  const guards = GUARD_SET.map((file): Guard => {
    const entry = entries.find((entry) => entry.file === file);
    const exclusion = receipt.exclusionChecks.find((entry) => entry.file === file);
    const sourceSha256 = receipt.sourceSha256[file]!;
    if (!entry) return {
      file, sourceSha256, state: exclusion ? "excluded" : "missing",
      population: population([], Boolean(exclusion)), mutants: [], ...(exclusion ? { exclusion } : {}),
    };
    demand(!exclusion, `${file}: simultaneously reported and excluded`);
    const source = text(entry.value.source, `${file} captured source`);
    demand(guardMutationDigest(source) === sourceSha256, `${file}: report source differs from captured source identity`);
    const mutants = unique(list(entry.value.mutants, `${file} mutants`).map((m) => readMutant(m, file, source)), (m) => m.id, `${file} mutant identity`).sort((a, b) => a.id.localeCompare(b.id));
    const counts = population(mutants);
    return { file, sourceSha256, state: measuredState(counts), population: counts, mutants };
  });
  return { schemaVersion: 1, identityVersion: "file-location-mutation-v1", receipt, guards };
}

function parseCensus(value: unknown, forUpdate: boolean): NormalizedGuardCensus {
  const x = record(value, "normalized census");
  demand(x.schemaVersion === 1 && x.identityVersion === "file-location-mutation-v1", "unsupported normalized census identity/schema version");
  const expectedGuards = forUpdate ? Object.keys(record(record(x.receipt, "capture receipt").sourceSha256, "sourceSha256")).map(guardPath) : [...GUARD_SET];
  demand(expectedGuards.length > 0, "historical baseline has no guard identities");
  const receipt = parseGuardMutationReceipt(x.receipt, expectedGuards);
  const guards = unique(list(x.guards, "guards").map((value): Guard => {
    const g = record(value, "guard");
    const file = guardPath(g.file);
    const sourceSha256 = hash(g.sourceSha256, `${file} sourceSha256`);
    demand(receipt.sourceSha256[file] === sourceSha256, `${file}: normalized source identity mismatch`);
    const mutants = unique(list(g.mutants, `${file} mutants`).map((m) => readMutant(m, file)), (m) => m.id, `${file} mutant identity`).sort((a, b) => a.id.localeCompare(b.id));
    const exclusion = own(g, "exclusion") ? exclusionCheck(g.exclusion) : undefined;
    const counts = population(mutants, Boolean(exclusion));
    const recorded = record(g.population, `${file} population`);
    demand(Object.keys(recorded).sort().join() === Object.keys(counts).sort().join(), `${file}: population fields missing or unknown`);
    for (const [key, value] of Object.entries(counts)) demand(integer(recorded[key], `${file} ${key}`) === value, `${file}: ${key} population is inconsistent`);
    const state = exclusion ? "excluded" : measuredState(counts);
    demand(g.state === state, `${file}: guard state is inconsistent`);
    if (exclusion) {
      demand(exclusion.file === file && mutants.length === 0, `${file}: invalid excluded population`);
      demand(JSON.stringify(exclusion) === JSON.stringify(receipt.exclusionChecks.find((entry) => entry.file === file)), `${file}: exclusion check differs from capture receipt`);
    } else demand(!receipt.exclusionChecks.some((entry) => entry.file === file), `${file}: missing normalized exclusion check`);
    return { file, sourceSha256, state, population: counts, mutants, ...(exclusion ? { exclusion } : {}) };
  }), (g) => g.file, "guard").sort((a, b) => a.file.localeCompare(b.file));
  demand(guards.map((g) => g.file).join() === [...expectedGuards].sort().join(), "baseline must identify every declared guard exactly");
  return { schemaVersion: 1, identityVersion: "file-location-mutation-v1", receipt, guards };
}

function kind(mutant: Mutant): string | undefined {
  if (mutant.status === "Killed" || mutant.status === "Timeout") return undefined;
  if (mutant.status === "Survived") return "survivor";
  return mutant.status === "NoCoverage" ? "no-coverage" : "unscored";
}

export function guardMutationReviewRequirements(census: NormalizedGuardCensus): { key: string; guard: Guard; mutant?: Mutant }[] {
  return census.guards.flatMap((guard) => {
    if (guard.exclusion) return [{ key: `exclusion:${guard.file}`, guard }];
    const entries: { key: string; guard: Guard; mutant?: Mutant }[] = guard.mutants.flatMap((mutant) => {
      const category = kind(mutant);
      return category ? [{ key: `${category}:${guard.file}:${mutant.id}`, guard, mutant }] : [];
    });
    if (guard.state === "unexercised" || guard.state === "unscored") entries.push({ key: `${guard.state}-guard:${guard.file}`, guard });
    return entries;
  });
}

function review(value: unknown, now: string, allowExpiredReasons = false): GuardMutationReview {
  const x = record(value, "review");
  const result: GuardMutationReview = {
    key: text(x.key, "review key"), owner: text(x.owner, "review owner"), reviewedAt: date(x.reviewedAt, "reviewedAt"), reviewedBy: text(x.reviewedBy, "reviewedBy"),
    sourceCommit: commit(x.sourceCommit, "review sourceCommit"), sourceSha256: hash(x.sourceSha256, "review sourceSha256"), reportSha256: hash(x.reportSha256, "review reportSha256"),
  };
  demand(Date.parse(result.reviewedAt) <= Date.parse(now), `${result.key}: review is dated in the future`);
  if (own(x, "remediationIssue")) {
    result.remediationIssue = text(x.remediationIssue, "remediation issue");
    demand(/^https:\/\/github\.com\/jharvieux\/Harvey\/issues\/[1-9]\d*$/.test(result.remediationIssue), "remediation issue must name an issue in jharvieux/Harvey");
  }
  if (own(x, "reason")) {
    result.reason = text(x.reason, "bounded review reason");
    result.expiresAt = date(x.expiresAt, "reason expiresAt");
    demand(allowExpiredReasons || Date.parse(result.expiresAt) > Date.parse(now), `${result.key}: bounded reason has expired`);
    demand(Date.parse(result.expiresAt) > Date.parse(result.reviewedAt), `${result.key}: reason expires before it is reviewed`);
    demand(Date.parse(result.expiresAt) - Date.parse(result.reviewedAt) <= 90 * 24 * 60 * 60 * 1000, `${result.key}: reason must be bounded to at most 90 days`);
  }
  demand(result.remediationIssue || result.reason, `${result.key}: an owner needs a remediation issue or bounded reason`);
  return result;
}

function validateReviews(census: NormalizedGuardCensus, values: unknown, now: string, allowExpiredReasons = false): GuardMutationReview[] {
  const reviews = unique(list(values, "reviews").map((x) => review(x, now, allowExpiredReasons)), (r) => r.key, "review key");
  const required = guardMutationReviewRequirements(census);
  for (const row of required) {
    const r = reviews.find((review) => review.key === row.key);
    demand(r, `missing owner/remediation review for ${row.key}`);
    demand(r.sourceSha256 === row.guard.sourceSha256, `${row.key}: last-reviewed source is stale`);
  }
  for (const r of reviews) demand(required.some((row) => row.key === r.key), `stale review: ${r.key}`);
  return reviews.sort((a, b) => a.key.localeCompare(b.key));
}

function measurementProblems(census: NormalizedGuardCensus): string[] {
  const problems: string[] = [];
  for (const guard of census.guards) {
    if (guard.state === "missing") problems.push(`missing-guard: ${guard.file}`);
    else if (guard.exclusion?.outcome === "measurable") problems.push(`stale-exclusion: ${guard.file} is measurable; include it in a complete mutation run before reducing the baseline`);
    else if (guard.exclusion?.outcome === "uncheckable") problems.push(`uncheckable-exclusion: ${guard.file}: ${guard.exclusion.detail}`);
    else if (!guard.exclusion && guard.population.attempted === 0) problems.push(`unexercised-guard: ${guard.file} produced zero mutants`);
  }
  if (census.guards.reduce((sum, g) => sum + g.population.attempted, 0) === 0) problems.push("empty-census: zero examined mutants is not evidence");
  if (census.guards.reduce((sum, g) => sum + g.population.killed + g.population.survived, 0) === 0) problems.push("unscored-census: no mutant was exercised by a test");
  return problems;
}

export function parseGuardMutationBaseline(value: unknown, now = new Date().toISOString(), forUpdate = false): GuardMutationBaseline {
  const x = record(value, "guard mutation baseline");
  demand(x.schemaVersion === 1, "unsupported baseline schemaVersion");
  const census = parseCensus(x.census, forUpdate);
  const problems = measurementProblems(census);
  demand(problems.length === 0, `invalid baseline measurement: ${problems.join("; ")}`);
  return { schemaVersion: 1, census, reviews: validateReviews(census, x.reviews, now, forUpdate) };
}

export function compareGuardMutationCensus(census: NormalizedGuardCensus, baseline: GuardMutationBaseline): { ok: boolean; problems: string[]; delta: string[] } {
  const problems = measurementProblems(census);
  const delta: string[] = [];
  if (JSON.stringify(census.receipt.toolchain) !== JSON.stringify(baseline.census.receipt.toolchain)) problems.push("toolchain-changed: exact Node/package identities differ; explicit baseline review is required");
  const previous = guardMutationReviewRequirements(baseline.census);
  const current = guardMutationReviewRequirements(census);
  for (const row of current) {
    if (!previous.some((before) => before.key === row.key)) {
      const message = `new-${row.key}`;
      problems.push(message); delta.push(`ADD ${row.key}`);
    } else {
      const reviewed = baseline.reviews.find((r) => r.key === row.key)!;
      if (reviewed.sourceSha256 !== row.guard.sourceSha256) problems.push(`stale-provenance: ${row.key}; source changed since review`);
    }
  }
  for (const row of previous) {
    if (!current.some((after) => after.key === row.key)) {
      problems.push(`stale-${row.key}: no longer present in the measured population`);
      delta.push(`REMOVE ${row.key}`);
    }
  }
  for (const guard of census.guards) {
    const before = baseline.census.guards.find((g) => g.file === guard.file);
    if (!before) {
      problems.push(`new-guard: ${guard.file}; record its measured population explicitly`);
      delta.push(`ADD GUARD ${guard.file}: ${JSON.stringify(guard.population)}`);
      continue;
    }
    if (guard.state !== before.state) {
      delta.push(`STATE ${guard.file}: ${before.state} -> ${guard.state}`);
      if (guard.state === "unexercised" || guard.state === "unscored") problems.push(`new-${guard.state}-guard: ${guard.file}`);
    }
    if (guard.exclusion && before.exclusion && guard.exclusion.detail !== before.exclusion.detail) problems.push(`changed-exclusion-evidence: ${guard.file}; the current failure needs review`);
    for (const category of Object.keys(guard.population) as (keyof Population)[]) {
      if (guard.population[category] !== before.population[category]) delta.push(`POPULATION ${guard.file} ${category}: ${before.population[category]} -> ${guard.population[category]}`);
    }
    if (!guard.exclusion && guard.state !== "missing" && before.sourceSha256 === guard.sourceSha256) {
      const missing = before.mutants.filter((m) => !guard.mutants.some((current) => current.id === m.id));
      for (const m of missing) problems.push(`missing-mutant: ${guard.file}:${m.id}; unchanged source lost a measured mutant`);
    }
  }
  if (JSON.stringify(census.receipt.toolchain) !== JSON.stringify(baseline.census.receipt.toolchain)) delta.push(`TOOLCHAIN ${JSON.stringify(baseline.census.receipt.toolchain)} -> ${JSON.stringify(census.receipt.toolchain)}`);
  if (census.receipt.configSha256 !== baseline.census.receipt.configSha256) delta.push(`CONFIG ${baseline.census.receipt.configSha256} -> ${census.receipt.configSha256}`);
  return { ok: problems.length === 0, problems: [...new Set(problems)].sort(), delta: delta.sort() };
}

export function updateGuardMutationBaseline(census: NormalizedGuardCensus, previous: GuardMutationBaseline | undefined, suppliedReviews: unknown, now = new Date().toISOString()): { baseline: GuardMutationBaseline; delta: string[] } {
  const problems = measurementProblems(census);
  demand(problems.length === 0, `cannot baseline an incomplete measurement: ${problems.join("; ")}`);
  if (previous) {
    const lost = compareGuardMutationCensus(census, previous).problems.filter((problem) => problem.startsWith("missing-mutant:"));
    demand(lost.length === 0, `cannot reduce an unchanged source's attempted population: ${lost.join("; ")}`);
  }
  const supplied = unique(list(suppliedReviews, "update reviews").map((r) => review(r, now)), (r) => r.key, "update review");
  const required = guardMutationReviewRequirements(census);
  for (const r of supplied) {
    demand(required.some((row) => row.key === r.key), `update review does not name a current measured row: ${r.key}`);
    demand(r.reportSha256 === census.receipt.reportSha256 && r.sourceCommit === census.receipt.sourceCommit, `${r.key}: new review must cite this capture's report and commit`);
    demand(Date.parse(r.reviewedAt) >= Date.parse(census.receipt.finishedAt), `${r.key}: review predates the measurement`);
  }
  for (const g of census.guards) {
    const before = previous?.census.guards.find((old) => old.file === g.file);
    if (g.exclusion && before?.exclusion && g.exclusion.detail !== before.exclusion.detail) demand(supplied.some((r) => r.key === `exclusion:${g.file}`), `${g.file}: changed exclusion failure requires a fresh review`);
  }
  const merged = required.flatMap((row) => {
    const r = supplied.find((r) => r.key === row.key) ?? previous?.reviews.find((r) => r.key === row.key);
    return r ? [r] : [];
  });
  const reviews = validateReviews(census, merged, now);
  const baseline: GuardMutationBaseline = { schemaVersion: 1, census, reviews };
  const delta = previous ? compareGuardMutationCensus(census, previous).delta : ["CREATE baseline", ...required.map((row) => `ADD ${row.key}`), ...census.guards.map((g) => `POPULATION ${g.file}: ${JSON.stringify(g.population)}`)];
  for (const r of reviews) if (JSON.stringify(r) !== JSON.stringify(previous?.reviews.find((old) => old.key === r.key))) delta.push(`REVIEW ${r.key}: owner=${r.owner}; ${r.remediationIssue ?? `${r.reason} (expires ${r.expiresAt})`}; source=${r.sourceSha256}`);
  return { baseline, delta: delta.sort() };
}
