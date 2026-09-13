import { createHash } from "node:crypto";

/** Internal census vocabulary; this does not change a finding or client report. */
export const ENVIRONMENT_CLASSES = [
  "tool", "runtime", "package-manager", "database", "runner-image", "shell",
  "locale", "clock", "mutable-data", "source-revision", "hardware", "unresolved",
] as const;
export type EnvironmentClass = (typeof ENVIRONMENT_CLASSES)[number];
export type BindingState = "pinned" | "recorded" | "accepted" | "wholly-unbound";

export interface EvidenceLocation { path: string; anchor: string; line: number }
export interface EnvironmentDependencyRow {
  id: string;
  venue: string;
  evidence: EvidenceLocation;
  consumer: { location: EvidenceLocation | null; resolution: "authoritative" | "unresolved"; reason: string };
  dependencyClass: EnvironmentClass;
  classification: "residual-unresolved" | "vocabulary-candidate" | "authoritative-record";
  dependency: string;
  observedIdentity: string | null;
  identitySource: EvidenceLocation | null;
  pinSource: { location: EvidenceLocation; identity: string; scope: "environment-behavior" | "output-schema" | "artifact-integrity" } | null;
  assertionVenue: { location: EvidenceLocation; scope: "environment-behavior" | "output-schema" | "artifact-integrity"; claim: string } | null;
  freshness: { requirement: string; observedAt: string | null; expiresAt: string | null; enforcedBy: EvidenceLocation | null };
  state: BindingState;
  resolution: "identified" | "dynamic" | "unresolved";
  owner: string;
  schemaOwner: string | null;
  environmentOwner: string;
  links: string[];
  reason: string;
}

export interface EvidenceVenue {
  id: string;
  path: string;
  kind: "source" | "structured-data" | "workflow" | "document" | "opaque";
  format: string;
  sha256: string;
  gitMode: string;
  gitOid: string;
  bytes: number;
  literalCount: number;
  literalSha256: string | null;
  owner: string;
  disposition: "authoritative-adapter" | "conservative-candidate" | "opaque-unresolved";
  reason: string;
}

export interface CensusReconciliation {
  registry: string;
  owner: string;
  state: "present" | "not-present-at-base" | "identity-disagreement";
  members: { key: string; evidence: EvidenceLocation; rowIds: string[]; reason: string }[];
  reason: string;
}

export interface EnvironmentInventory {
  schemaVersion: 1;
  source: { commit: string; tree: string; commitPayload: string; excludedObjects: { path: string; gitMode: string; gitOid: string }[]; mode: "committed" | "working-tree"; populationSha256: string };
  analyzer: { version: 1; classes: EnvironmentClass[]; scope: "all-git-blobs" };
  venues: EvidenceVenue[];
  rows: EnvironmentDependencyRow[];
  reconciliations: CensusReconciliation[];
  population: {
    venues: number; rows: number; authoritativeVenues: number; candidateVenues: number; opaqueVenues: number; environmentAssertions: number; schemaAssertions: number;
    residualRows: number; vocabularyCandidates: number; authoritativeRecords: number; authoritativeObservedIdentities: number; authoritativeUnresolved: number; authoritativeDynamic: number;
    classes: { dependencyClass: EnvironmentClass; rows: number; pinned: number; recorded: number; accepted: number; whollyUnbound: number; dynamic: number; unresolved: number; emptyReason: string | null }[];
  };
  exclusions: { path: string; owner: string; reason: string }[];
  limitations: string[];
}

export function censusDigest(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }

/** Git's object hash authenticates a retained commit/tree even after a squash or shallow clone. */
export function censusGitObject(kind: "commit" | "tree" | "blob", bytes: Buffer): string {
  return createHash("sha1").update(`${kind} ${bytes.length}\0`).update(bytes).digest("hex");
}

function treeIdentity(entries: { path: string; gitMode: string; gitOid: string }[]): string {
  const members = new Map<string, { gitMode: string; gitOid: string }>();
  const directories = new Map<string, typeof entries>();
  for (const entry of entries) {
    if (!entry.path || entry.path.split("/").some((p) => !p || p === "." || p === "..") || entry.path.includes("\0")) throw new Error("environment census: invalid Git tree path");
    const slash = entry.path.indexOf("/");
    if (slash < 0) { if (members.has(entry.path)) throw new Error("environment census: duplicate Git tree path"); members.set(entry.path, entry); }
    else { const name = entry.path.slice(0, slash); directories.set(name, [...(directories.get(name) ?? []), { ...entry, path: entry.path.slice(slash + 1) }]); }
  }
  for (const [name, children] of directories) { if (members.has(name)) throw new Error("environment census: conflicting Git tree path"); members.set(name, { gitMode: "40000", gitOid: treeIdentity(children) }); }
  const ordered = [...members.entries()].sort(([a, x], [b, y]) => Buffer.compare(Buffer.from(a + (x.gitMode === "40000" ? "/" : "")), Buffer.from(b + (y.gitMode === "40000" ? "/" : ""))));
  return censusGitObject("tree", Buffer.concat(ordered.flatMap(([name, entry]) => [Buffer.from(`${entry.gitMode} ${name}\0`), Buffer.from(entry.gitOid, "hex")])));
}

export function censusJson(value: unknown): string {
  const ordered = (v: unknown): unknown => Array.isArray(v) ? v.map(ordered)
    : v !== null && typeof v === "object" ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, x]) => [k, ordered(x)])) : v;
  return `${JSON.stringify(ordered(value), null, 2)}\n`;
}

export function censusPopulation(venues: EvidenceVenue[], rows: EnvironmentDependencyRow[]): EnvironmentInventory["population"] {
  return {
    venues: venues.length, rows: rows.length,
    authoritativeVenues: venues.filter((v) => v.disposition === "authoritative-adapter").length,
    candidateVenues: venues.filter((v) => v.disposition === "conservative-candidate").length,
    opaqueVenues: venues.filter((v) => v.disposition === "opaque-unresolved").length,
    environmentAssertions: rows.filter((r) => r.assertionVenue?.scope === "environment-behavior").length,
    schemaAssertions: rows.filter((r) => r.assertionVenue?.scope === "output-schema").length,
    residualRows: rows.filter((r) => r.classification === "residual-unresolved").length,
    vocabularyCandidates: rows.filter((r) => r.classification === "vocabulary-candidate").length,
    authoritativeRecords: rows.filter((r) => r.classification === "authoritative-record").length,
    authoritativeObservedIdentities: rows.filter((r) => r.classification === "authoritative-record" && r.observedIdentity !== null).length,
    authoritativeUnresolved: rows.filter((r) => r.classification === "authoritative-record" && r.resolution === "unresolved").length,
    authoritativeDynamic: rows.filter((r) => r.classification === "authoritative-record" && r.resolution === "dynamic").length,
    classes: ENVIRONMENT_CLASSES.map((dependencyClass) => {
      const members = rows.filter((row) => row.dependencyClass === dependencyClass);
      return { dependencyClass, rows: members.length,
        pinned: members.filter((r) => r.state === "pinned").length,
        recorded: members.filter((r) => r.state === "recorded").length,
        accepted: members.filter((r) => r.state === "accepted").length,
        whollyUnbound: members.filter((r) => r.state === "wholly-unbound").length,
        dynamic: members.filter((r) => r.resolution === "dynamic").length,
        unresolved: members.filter((r) => r.resolution === "unresolved").length,
        emptyReason: members.length ? null : "No dependency was identified in the retained content/adapter population. This is not proof that this environment input cannot affect execution.",
      };
    }),
  };
}

/** Validate the serialized boundary before comparing it; counts cannot hide missing rows. */
export function validateEnvironmentInventory(value: unknown): asserts value is EnvironmentInventory {
  const fail = (message: string): never => { throw new Error(`environment census: ${message}`); };
  const record = (v: unknown, name: string): Record<string, unknown> => v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : fail(`${name} must be an object`);
  const text = (v: unknown, name: string): string => typeof v === "string" && v.trim() ? v : fail(`${name} must be nonempty`);
  const location = (v: unknown, name: string): void => { const x = record(v, name); text(x.path, `${name}.path`); text(x.anchor, `${name}.anchor`); if (!Number.isInteger(x.line) || Number(x.line) < 1) fail(`${name}.line must be positive`); };
  const x = record(value, "inventory");
  if (x.schemaVersion !== 1) fail("unsupported schemaVersion");
  const source = record(x.source, "source");
  for (const key of ["commit", "tree"] as const) if (!/^[a-f0-9]{40}$/.test(text(source[key], `source.${key}`))) fail(`source.${key} must be immutable`);
  if (!["committed", "working-tree"].includes(String(source.mode))) fail("unknown source mode");
  if (!/^[a-f0-9]{64}$/.test(String(source.populationSha256))) fail("invalid population digest");
  const commitPayload = Buffer.from(text(source.commitPayload, "source.commitPayload"), "base64");
  if (censusGitObject("commit", commitPayload) !== source.commit || !commitPayload.toString().startsWith(`tree ${source.tree}\n`)) fail("immutable commit proof does not reconcile");
  if (!Array.isArray(source.excludedObjects)) fail("excluded Git objects must be retained");
  const analyzer = record(x.analyzer, "analyzer");
  if (analyzer.version !== 1 || analyzer.scope !== "all-git-blobs" || censusJson(analyzer.classes) !== censusJson(ENVIRONMENT_CLASSES)) fail("unregistered dependency class or analyzer");
  if (![x.venues, x.rows, x.reconciliations, x.exclusions, x.limitations].every(Array.isArray)) fail("population arrays are required");
  const inventory = value as EnvironmentInventory;
  if (!inventory.venues.length || !inventory.rows.length) fail("empty examined population");
  const venues = new Set<string>();
  for (const venue of inventory.venues) {
    if (venues.has(text(venue.id, "venue.id"))) fail(`duplicate venue ${venue.id}`);
    venues.add(venue.id);
    text(venue.path, "venue.path"); text(venue.owner, "venue.owner"); text(venue.reason, "venue.reason");
    if (!/^[a-f0-9]{64}$/.test(venue.sha256) || !Number.isInteger(venue.bytes) || venue.bytes < 0) fail(`invalid venue receipt ${venue.id}`);
    if (!/^[a-f0-9]{40}$/.test(venue.gitOid) || !["100644", "100755", "120000", "160000"].includes(venue.gitMode)) fail(`invalid Git object receipt ${venue.id}`);
    if (!["source", "structured-data", "workflow", "document", "opaque"].includes(venue.kind)) fail(`unregistered venue kind ${venue.id}`);
    if (!["authoritative-adapter", "conservative-candidate", "opaque-unresolved"].includes(venue.disposition)) fail(`unregistered disposition ${venue.id}`);
  }
  const ids = new Set<string>();
  for (const row of inventory.rows) {
    if (ids.has(text(row.id, "row.id"))) fail(`duplicate row ${row.id}`);
    ids.add(row.id);
    if (!venues.has(row.venue)) fail(`orphan row ${row.id}`);
    if (!ENVIRONMENT_CLASSES.includes(row.dependencyClass)) fail(`unregistered dependency class ${row.dependencyClass}`);
    if (!["residual-unresolved", "vocabulary-candidate", "authoritative-record"].includes(row.classification)) fail(`unregistered row classification ${row.id}`);
    for (const key of ["dependency", "owner", "environmentOwner", "reason"] as const) text(row[key], `row.${key}`);
    location(row.evidence, "evidence");
    const consumer = record(row.consumer, "consumer"); text(consumer.reason, "consumer.reason");
    if (!["authoritative", "unresolved"].includes(String(consumer.resolution))) fail("unregistered consumer resolution");
    if (consumer.resolution === "authoritative") location(consumer.location, "consumer.location");
    if (row.observedIdentity !== null) { text(row.observedIdentity, "observedIdentity"); location(row.identitySource, "identitySource"); }
    const scopes = ["environment-behavior", "output-schema", "artifact-integrity"];
    if (row.pinSource !== null) { location(row.pinSource.location, "pinSource"); text(row.pinSource.identity, "pinSource.identity"); if (!scopes.includes(row.pinSource.scope)) fail(`unknown pin scope ${row.id}`); }
    if (row.assertionVenue !== null) { location(row.assertionVenue.location, "assertionVenue"); text(row.assertionVenue.claim, "assertionVenue.claim"); if (!scopes.includes(row.assertionVenue.scope)) fail(`unknown assertion scope ${row.id}`); }
    if (!["pinned", "recorded", "accepted", "wholly-unbound"].includes(row.state)) fail(`unknown state ${row.id}`);
    if (!["identified", "dynamic", "unresolved"].includes(row.resolution)) fail(`unknown resolution ${row.id}`);
    if (row.state === "pinned" && (!row.observedIdentity || !row.identitySource || !row.pinSource || row.pinSource.identity !== row.observedIdentity || !row.assertionVenue || row.consumer.resolution !== "authoritative")) fail(`unproven identity pin ${row.id}`);
    if (row.state === "recorded" && !row.observedIdentity) fail(`recorded identity missing ${row.id}`);
    if (row.classification !== "authoritative-record" && (row.state !== "wholly-unbound" || row.resolution !== "unresolved" || row.observedIdentity !== null || row.pinSource !== null || row.assertionVenue !== null || row.consumer.resolution !== "unresolved")) fail(`unresolved candidate was promoted ${row.id}`);
    const freshness = record(row.freshness, "freshness"); text(freshness.requirement, "freshness.requirement");
    for (const key of ["observedAt", "expiresAt"] as const) if (freshness[key] !== null && (typeof freshness[key] !== "string" || !Number.isFinite(Date.parse(String(freshness[key]))))) fail(`invalid ${key} ${row.id}`);
    if (!Array.isArray(row.links)) fail(`row links missing ${row.id}`);
  }
  for (const venue of venues) if (inventory.rows.filter((row) => row.venue === venue && row.classification === "residual-unresolved").length !== 1) fail(`venue needs exactly one residual owned row/reason ${venue}`);
  for (const r of inventory.reconciliations) {
    text(r.registry, "registry"); text(r.owner, "registry.owner"); text(r.reason, "registry.reason");
    for (const member of r.members) { location(member.evidence, "registry.evidence"); text(member.key, "registry.key"); text(member.reason, "registry.member.reason"); if (!member.rowIds.length || member.rowIds.some((id) => !ids.has(id))) fail(`registry orphan ${member.key}`); }
    if (new Set(r.members.map((m) => m.key)).size !== r.members.length) fail(`duplicate registry member ${r.registry}`);
  }
  if (censusJson(censusPopulation(inventory.venues, inventory.rows)) !== censusJson(inventory.population)) fail("population does not reconcile");
  if (censusDigest(censusJson(inventory.venues.map(({ path, sha256, bytes }) => ({ path, sha256, bytes })))) !== inventory.source.populationSha256) fail("population receipt does not reconcile");
  const exclusions = new Set(inventory.exclusions.map((e) => e.path));
  for (const entry of inventory.source.excludedObjects) if (!exclusions.has(entry.path) || !/^[a-f0-9]{40}$/.test(entry.gitOid) || !["100644", "100755", "120000", "160000"].includes(entry.gitMode)) fail("unregistered excluded Git object");
  if (source.mode === "committed" && treeIdentity([...inventory.venues, ...inventory.source.excludedObjects]) !== source.tree) fail("immutable tree proof does not reconcile");
}
