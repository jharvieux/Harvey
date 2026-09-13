import { applyCensusAdapters } from "./environment-dependency-census-adapters.js";
import { CENSUS_SELF_PATHS, discoverCensusVenue, type CensusSnapshot } from "./environment-dependency-census-discovery.js";
import { censusDigest, censusJson, censusPopulation, ENVIRONMENT_CLASSES, validateEnvironmentInventory, type EnvironmentInventory } from "./environment-dependency-census-schema.js";

export function buildEnvironmentInventory(snapshot: CensusSnapshot): EnvironmentInventory {
  const venues = snapshot.files.map(discoverCensusVenue);
  const { rows, reconciliations } = applyCensusAdapters(snapshot, venues);
  const inventory: EnvironmentInventory = {
    schemaVersion: 1,
    source: { commit: snapshot.commit, tree: snapshot.tree, commitPayload: snapshot.commitPayload, excludedObjects: snapshot.excludedObjects, mode: snapshot.mode, populationSha256: censusDigest(censusJson(venues.map(({ path, sha256, bytes }) => ({ path, sha256, bytes })))) },
    analyzer: { version: 1, classes: [...ENVIRONMENT_CLASSES], scope: "all-git-blobs" },
    venues, rows, reconciliations, population: censusPopulation(venues, rows),
    exclusions: CENSUS_SELF_PATHS.map((path) => ({ path, owner: "#1906 generated census outputs", reason: "Derived census output excluded to prevent a recursive content digest. Implementation, CLI, tests and unknown future census files are ordinary measured inputs. The inventory schema and semantic comparison validate this output separately." })),
    limitations: [
      "This is an offline immutable-source inventory, not a new audit, tool run, live falsifier, current freshness verdict or behavioral equivalence certification. A static assertion venue records code availability, not execution.",
      "Every committed blob is counted by path, original byte digest and content-format disposition. File receipts are a discovery denominator, not a count of known evidence consumers. Every file, including adapted files, retains an unresolved-content row.",
      "Retained commit payload and per-path Git object identities reconstruct the immutable commit/tree, including excluded circular outputs. This proof survives a squash/shallow checkout and rejects relabelled source SHAs; it does not prove an environment assertion executed.",
      "Content hints are conservative candidates. Unlabelled numbers/strings, arbitrary computation, indirect consumers, reflection, generated-at-runtime inputs and external state cannot be exhaustively classified statically. Regeneration preserves these residuals rather than accepting them.",
      "Known fixture, reason, target/module, advisory, baseline and family adapters add positively identified records with separate schema and environment owners. An identity pin, artifact-integrity check and environment-behavior assertion are different facts.",
      "Gitlink/symlink destinations and opaque/non-UTF-8 files are not followed or executed. Gzip is decoded with a 128 MiB ceiling; undecodable content stays visible as opaque-unresolved with original-byte identity.",
      "Remote repository contents, uncommitted ignored artifacts, GitHub API history not committed here, actual hosted image digests, secret-bearing live targets and external databases are outside the immutable tree. Their unresolved/dynamic dependencies remain explicit where known.",
      "Class totals count retained rows, including conservative unresolved references. A zero class means no identified row in this analyzer's scope; it does not prove absence while unclassified content remains.",
      "#1853 owns the future external-corpus schema migration; this adapter reports the committed monolith and current advisory schema separately. #1901 owns captured-output properties; #1909 owns shared stability records. None is described as delivered by this census.",
    ],
  };
  validateEnvironmentInventory(inventory);
  return inventory;
}

export function compareEnvironmentInventory(current: EnvironmentInventory, recorded: unknown): { ok: boolean; problems: string[] } {
  validateEnvironmentInventory(current);
  validateEnvironmentInventory(recorded);
  if (recorded.source.mode !== "committed") throw new Error("environment census: the retained inventory must come from an immutable committed revision");
  const problems: string[] = [];
  const before = new Map(recorded.venues.map((v) => [v.id, v]));
  const after = new Map(current.venues.map((v) => [v.id, v]));
  for (const venue of current.venues) {
    const prior = before.get(venue.id);
    if (!prior) problems.push(`unregistered-venue: ${venue.path} needs an owned row or explicit unresolved reason in a regenerated immutable census`);
    else if (censusJson(venue) !== censusJson(prior)) problems.push(`changed-venue: ${venue.path}; content, literal receipt, ownership or format changed`);
  }
  for (const venue of recorded.venues) if (!after.has(venue.id)) problems.push(`removed-venue: ${venue.path}; the retained population no longer exists`);
  const priorRows = new Map(recorded.rows.map((r) => [r.id, r]));
  const nextRows = new Map(current.rows.map((r) => [r.id, r]));
  for (const r of current.rows) {
    if (!priorRows.has(r.id)) problems.push(`unregistered-dependency: ${r.id}`);
    else if (censusJson(r) !== censusJson(priorRows.get(r.id))) problems.push(`changed-dependency: ${r.id}`);
  }
  for (const r of recorded.rows) if (!nextRows.has(r.id)) problems.push(`removed-dependency: ${r.id}`);
  if (censusJson(current.reconciliations) !== censusJson(recorded.reconciliations)) problems.push("registry-reconciliation-changed: existing owner population or links differ");
  if (censusJson(current.exclusions) !== censusJson(recorded.exclusions) || censusJson(current.limitations) !== censusJson(recorded.limitations)) problems.push("scope-changed: exclusions or limitations require regenerated evidence");
  if (censusJson(current.analyzer) !== censusJson(recorded.analyzer)) problems.push("analyzer-changed: dependency vocabulary requires regenerated evidence");
  return { ok: problems.length === 0, problems };
}

export function summarizeEnvironmentInventory(inventory: EnvironmentInventory): string {
  const p = inventory.population;
  return [
    `Environment dependency census: ${inventory.source.commit} (${inventory.source.mode})`,
    `Discovery receipts: ${p.venues} blobs; ${p.authoritativeVenues} with authoritative adapters, ${p.candidateVenues} conservative candidates, ${p.opaqueVenues} opaque unresolved.`,
    `Rows are separate populations: ${p.residualRows} residual-content rows, ${p.vocabularyCandidates} vocabulary candidates, ${p.authoritativeRecords} authoritative records.`,
    `Authoritative records: ${p.authoritativeObservedIdentities} observed identities; ${p.authoritativeUnresolved} unresolved, ${p.authoritativeDynamic} dynamic. Every blob retains a residual unresolved-content row.`,
    `Declared assertion venues: ${p.environmentAssertions} environment-behavior, ${p.schemaAssertions} output-schema; assertions were not executed by this census.`,
    ...p.classes.map((c) => `${c.dependencyClass}: ${c.rows} rows; pinned=${c.pinned}, recorded=${c.recorded}, accepted=${c.accepted}, wholly-unbound=${c.whollyUnbound}, dynamic=${c.dynamic}, unresolved=${c.unresolved}${c.emptyReason ? `; ${c.emptyReason}` : ""}`),
  ].join("\n");
}
