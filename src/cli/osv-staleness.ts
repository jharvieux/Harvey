// Check every curated advisory claim against the live OSV record. This is intentionally outside
// the offline verify gate: the scheduled run detects upstream advisory drift.
import "./sync-stdio.js";
import { CURATED_CLAIMS, type CuratedClaim } from "../scan/dependencies.js";

interface Semver {
  major: bigint;
  minor: bigint;
  patch: bigint;
  prerelease: string[];
}

interface Event {
  kind: "introduced" | "fixed" | "last_affected" | "limit";
  raw: string;
  version?: Semver;
}

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const EVENT_KEYS = ["introduced", "fixed", "last_affected", "limit"] as const;

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseSemver(value: string): Semver | undefined {
  const match = SEMVER.exec(value);
  if (!match) return undefined;
  const prerelease = match[4]?.split(".") ?? [];
  if (prerelease.some((part) => /^\d+$/.test(part) && part.length > 1 && part[0] === "0")) return undefined;
  return { major: BigInt(match[1]!), minor: BigInt(match[2]!), patch: BigInt(match[3]!), prerelease };
}

function compare(left: Semver, right: Semver): number {
  for (const key of ["major", "minor", "patch"] as const) {
    const difference = left[key] - right[key];
    if (difference !== 0n) return difference < 0n ? -1 : 1;
  }
  if (left.prerelease.length === 0) return right.prerelease.length === 0 ? 0 : 1;
  if (right.prerelease.length === 0) return -1;
  for (let index = 0; index < Math.max(left.prerelease.length, right.prerelease.length); index++) {
    const a = left.prerelease[index];
    const b = right.prerelease[index];
    if (a === undefined) return -1;
    if (b === undefined) return 1;
    const aNumeric = /^\d+$/.test(a);
    const bNumeric = /^\d+$/.test(b);
    if (aNumeric !== bNumeric) return aNumeric ? -1 : 1;
    if (aNumeric) {
      const difference = BigInt(a) - BigInt(b);
      if (difference !== 0n) return difference < 0n ? -1 : 1;
    } else if (a !== b) {
      return a < b ? -1 : 1;
    }
  }
  return 0;
}

function parseEvent(value: unknown): Event | string {
  if (!record(value) || Object.keys(value).length !== 1) return "an event must contain exactly one boundary";
  const [kind, raw] = Object.entries(value)[0]!;
  if (!EVENT_KEYS.some((key) => key === kind)) return `unsupported ${kind} event`;
  if (typeof raw !== "string" || raw.length === 0) return `${kind} boundary is not a nonempty string`;
  if (kind === "introduced" && raw === "0") return { kind, raw };
  if (kind === "limit" && raw.includes("*")) return { kind, raw };
  const version = parseSemver(raw);
  if (!version) return `${kind} boundary ${JSON.stringify(raw)} is not an exact semantic version`;
  return { kind: kind as Event["kind"], raw, version };
}

function eventOrder(left: Event, right: Event): number {
  if (!left.version) return right.version ? -1 : 0;
  if (!right.version) return 1;
  return compare(left.version, right.version);
}

// OSV's evaluation algorithm tests each affected entry's versions and ranges as a union. Limits
// filter a whole range before its sorted status events are evaluated, not individual intervals.
// https://ossf.github.io/osv-schema/#evaluation
function affectedAtFix(claim: CuratedClaim, vuln: unknown): string | undefined {
  if (!record(vuln) || !Array.isArray(vuln.affected)) return "the advisory has no valid affected array";
  const candidate = parseSemver(claim.fixed);
  if (!candidate) return `our fixed boundary ${claim.fixed} is not an exact semantic version`;
  let matched = false;
  let hasFixedEvent = false;
  let vulnerable = false;

  for (const [affectedIndex, affected] of vuln.affected.entries()) {
    if (!record(affected) || !record(affected.package) ||
        typeof affected.package.name !== "string" || typeof affected.package.ecosystem !== "string") {
      return `affected[${affectedIndex}] has malformed package identity`;
    }
    if (affected.package.name !== claim.pkg || affected.package.ecosystem !== "npm") continue;
    matched = true;
    const where = `affected[${affectedIndex}] for npm/${claim.pkg}`;
    if (affected.versions !== undefined && !Array.isArray(affected.versions)) return `${where} has a malformed versions array`;
    if (affected.ranges !== undefined && !Array.isArray(affected.ranges)) return `${where} has a malformed ranges array`;
    if (affected.versions === undefined && affected.ranges === undefined) return `${where} has no versions or ranges`;
    for (const version of (affected.versions ?? []) as unknown[]) {
      if (typeof version !== "string") return `${where} has a non-string affected version`;
      if (version === claim.fixed) vulnerable = true;
    }
    for (const [rangeIndex, range] of ((affected.ranges ?? []) as unknown[]).entries()) {
      const rangeWhere = `${where} range[${rangeIndex}]`;
      if (!record(range) || range.type !== "SEMVER" || !Array.isArray(range.events) || range.events.length === 0) {
        return `${rangeWhere} has an unsupported type or malformed events`;
      }
      const events: Event[] = [];
      for (const raw of range.events) {
        const parsed = parseEvent(raw);
        if (typeof parsed === "string") return `${rangeWhere}: ${parsed}`;
        events.push(parsed);
        if (parsed.kind === "fixed" && parsed.raw === claim.fixed) hasFixedEvent = true;
      }
      if (!events.some((event) => event.kind === "introduced")) return `${rangeWhere} has no introduced event`;
      if (events.some((event) => event.kind === "fixed") && events.some((event) => event.kind === "last_affected")) {
        return `${rangeWhere} mixes fixed and last_affected events`;
      }
      const statusEvents = events.filter((event) => event.kind !== "limit").sort(eventOrder);
      let open = false;
      for (const [index, event] of statusEvents.entries()) {
        const previous = statusEvents[index - 1];
        if (previous && eventOrder(previous, event) === 0) return `${rangeWhere} has conflicting boundaries at one version`;
        if (event.kind === "introduced") {
          if (open) return `${rangeWhere} introduces an already open interval`;
          open = true;
        } else {
          if (!open) return `${rangeWhere} closes an unopened interval`;
          open = false;
        }
      }
      const limits = events.filter((event) => event.kind === "limit");
      if (limits.length > 0 && !limits.some((event) => !event.version || compare(candidate, event.version) < 0)) continue;
      let inRange = false;
      for (const event of statusEvents) {
        if (event.kind === "introduced" && (!event.version || compare(candidate, event.version) >= 0)) inRange = true;
        else if (event.kind === "fixed" && event.version && compare(candidate, event.version) >= 0) inRange = false;
        else if (event.kind === "last_affected" && event.version && compare(candidate, event.version) > 0) inRange = false;
      }
      if (inRange) vulnerable = true;
    }
  }
  if (!matched) return `the advisory lists no affected entry for npm/${claim.pkg}`;
  if (!hasFixedEvent) return `the advisory lists no fixed event at ${claim.fixed} for npm/${claim.pkg}`;
  if (vulnerable) return `npm/${claim.pkg}@${claim.fixed} remains affected by a matching range or explicit version`;
  return undefined;
}

async function checkClaim(claim: CuratedClaim): Promise<string | undefined> {
  const res = await fetch(`https://api.osv.dev/v1/vulns/${claim.advisory}`);
  if (res.status === 404) return `${claim.advisory} 404s at OSV — withdrawn, rejected, or never existed`;
  if (!res.ok) return `${claim.advisory}: OSV returned HTTP ${res.status} — cannot verify`;

  const vuln: unknown = await res.json();
  if (!record(vuln)) return `${claim.advisory}: malformed OSV record`;
  if (vuln.withdrawn !== undefined) {
    if (typeof vuln.withdrawn !== "string" || !vuln.withdrawn) return `${claim.advisory}: malformed withdrawn timestamp`;
    return `${claim.advisory} was WITHDRAWN at OSV on ${vuln.withdrawn}`;
  }
  const problem = affectedAtFix(claim, vuln);
  return problem ? `${claim.advisory} (${claim.pkg}): ${problem}` : undefined;
}

async function main(): Promise<void> {
  console.log(`Verifying ${CURATED_CLAIMS.length} curated advisory claims against api.osv.dev\n`);
  const results = await Promise.all(
    CURATED_CLAIMS.map(async (claim) => {
      try {
        return { claim, drift: await checkClaim(claim) };
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        return { claim, drift: `${claim.advisory} (${claim.pkg}): cannot verify OSV response: ${reason}` };
      }
    }),
  );
  const drifted = results.filter((result) => result.drift !== undefined);
  for (const { claim, drift } of results) {
    console.log(`  ${drift ? "DRIFT" : "ok   "}  ${claim.note}`);
    if (drift) console.log(`         ${drift}`);
  }
  if (drifted.length > 0) {
    console.error(`\n${drifted.length} of ${CURATED_CLAIMS.length} curated claims no longer match OSV.`);
    console.error("Each one is a fact this scanner asserts to clients. Re-verify against the advisory and correct src/scan/dependencies.ts (see #212).");
    process.exit(1);
  }
  console.log(`\nAll ${CURATED_CLAIMS.length} curated claims still match OSV.`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
