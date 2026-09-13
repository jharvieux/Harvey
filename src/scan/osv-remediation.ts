interface OsvRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

interface OsvRange {
  type?: string;
  events?: OsvRangeEvent[];
}

export interface OsvAffectedPackage {
  package?: { name?: string; ecosystem?: string };
  ranges?: OsvRange[];
  versions?: string[];
}

interface OsvRemediation {
  fixedVersions: string[];
  fix: string;
}

interface Semver {
  major: bigint;
  minor: bigint;
  patch: bigint;
  prerelease: string[];
  original: string;
}

interface Interval {
  start?: Semver;
  end?: Semver;
  endInclusive: boolean;
}

interface ParsedEvent {
  kind: keyof OsvRangeEvent;
  version?: Semver;
  original: string;
}

const SEMVER = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function parseSemver(value: string): Semver | undefined {
  const match = SEMVER.exec(value.trim());
  if (!match) return undefined;
  const prerelease = match[4]?.split(".") ?? [];
  if (prerelease.some((identifier) => /^\d+$/.test(identifier) && identifier.length > 1 && identifier.startsWith("0"))) return undefined;
  return {
    major: BigInt(match[1]!),
    minor: BigInt(match[2]!),
    patch: BigInt(match[3]!),
    prerelease,
    original: value.trim().replace(/^v/, ""),
  };
}

function compareIdentifiers(left: string[], right: string[]): number {
  if (left.length === 0 && right.length === 0) return 0;
  if (left.length === 0) return 1;
  if (right.length === 0) return -1;
  for (let index = 0; index < Math.max(left.length, right.length); index++) {
    const a = left[index];
    const b = right[index];
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

function compare(left: Semver, right: Semver): number {
  for (const key of ["major", "minor", "patch"] as const) {
    const difference = left[key] - right[key];
    if (difference !== 0n) return difference < 0n ? -1 : 1;
  }
  return compareIdentifiers(left.prerelease, right.prerelease);
}

function event(entry: OsvRangeEvent): ParsedEvent | string {
  const populated = Object.entries(entry)
    .filter(([, value]) => value !== undefined);
  if (populated.length !== 1) return "an event does not contain exactly one supported boundary";
  const [kind, raw] = populated[0]!;
  if (!["introduced", "fixed", "last_affected", "limit"].includes(kind)) return `the ${String(kind)} event is unsupported`;
  if (typeof raw !== "string") return `the ${kind} boundary is not a string`;
  const original = raw.trim();
  const supportedKind = kind as keyof OsvRangeEvent;
  if (supportedKind === "introduced" && original === "0") return { kind: supportedKind, original };
  const version = parseSemver(original);
  if (!version) return `the ${supportedKind} boundary ${JSON.stringify(original)} is not an exact semantic version`;
  return { kind: supportedKind, version, original: version.original };
}

function inInterval(version: Semver, interval: Interval): boolean {
  if (interval.start && compare(version, interval.start) < 0) return false;
  if (!interval.end) return true;
  const endComparison = compare(version, interval.end);
  return interval.endInclusive ? endComparison <= 0 : endComparison < 0;
}

function remediationUnavailable(pkg: string, installed: string, advisory: string, fixedVersions: string[], reason: string): OsvRemediation {
  const prefix = fixedVersions.length === 0 ? `No fixed version is published for ${pkg} in ${advisory}. ` : "";
  return {
    fixedVersions,
    fix: `${prefix}A safe concrete upgrade cannot be established from the advisory's OSV ranges for ${pkg}@${installed}: ${reason}. Review ${advisory}, select a published version outside every affected interval, and verify the resolved lockfile version.`,
  };
}

/**
 * Derive advice only when the OSV record itself proves one exact published fix is outside all of
 * its affected SEMVER intervals. A branch-specific fix is not a universal lower bound: a later
 * release line can be vulnerable again.
 */
export function osvRemediation(pkg: string, installed: string, advisory: string, affected: OsvAffectedPackage[] | undefined, ecosystem?: string): OsvRemediation {
  const matching = (affected ?? []).filter((entry) =>
    entry.package?.name === pkg && (!ecosystem || !entry.package.ecosystem || entry.package.ecosystem === ecosystem));
  const rawFixed = matching.flatMap((entry) => entry.ranges ?? []).flatMap((range) => range.events ?? [])
    .flatMap((entry) => typeof entry.fixed === "string" && entry.fixed.trim() ? [entry.fixed.trim().replace(/^v/, "")] : []);
  const fixedVersions = [...new Set(rawFixed)].sort((left, right) => {
    const a = parseSemver(left);
    const b = parseSemver(right);
    return a && b ? compare(a, b) : a ? -1 : b ? 1 : left.localeCompare(right);
  });
  const current = parseSemver(installed);
  if (!current) return remediationUnavailable(pkg, installed, advisory, fixedVersions, "the installed version is not an exact semantic version");
  if (matching.length === 0) return remediationUnavailable(pkg, installed, advisory, fixedVersions, "the advisory has no affected entry for this package identity");

  const intervals: Interval[] = [];
  const candidates: Semver[] = [];
  const explicitlyAffected: Semver[] = [];
  for (const affectedPackage of matching) {
    if (affectedPackage.versions !== undefined && !Array.isArray(affectedPackage.versions)) {
      return remediationUnavailable(pkg, installed, advisory, fixedVersions, "the explicitly affected versions field is not an array");
    }
    for (const affectedVersion of affectedPackage.versions ?? []) {
      if (typeof affectedVersion !== "string") return remediationUnavailable(pkg, installed, advisory, fixedVersions, "an explicitly affected version is not a string");
      const parsed = parseSemver(affectedVersion);
      if (!parsed) return remediationUnavailable(pkg, installed, advisory, fixedVersions, `the explicitly affected version ${JSON.stringify(affectedVersion)} is not an exact semantic version`);
      explicitlyAffected.push(parsed);
    }
    for (const range of affectedPackage.ranges ?? []) {
      if (range.type !== "SEMVER") {
        return remediationUnavailable(pkg, installed, advisory, fixedVersions, range.type ? `it includes an unsupported ${range.type} range` : "it includes a range with no declared type");
      }
      // OSV limits filter the whole range; closing an interval at each limit invents safe gaps.
      // https://ossf.github.io/osv-schema/#evaluation defines the separate BeforeLimits step.
      if (range.events?.some((entry) => entry.limit !== undefined)) {
        return remediationUnavailable(pkg, installed, advisory, fixedVersions, "limit-bearing SEMVER ranges are not supported for safe upgrade selection");
      }
      const parsed: ParsedEvent[] = [];
      for (const entry of range.events ?? []) {
        const result = event(entry);
        if (typeof result === "string") return remediationUnavailable(pkg, installed, advisory, fixedVersions, result);
        parsed.push(result);
      }
      const unique = [...new Map(parsed.map((entry) => [`${entry.kind}:${entry.original}`, entry])).values()];
      unique.sort((left, right) => {
        if (!left.version) return right.version ? -1 : 0;
        if (!right.version) return 1;
        const order = compare(left.version, right.version);
        if (order !== 0) return order;
        // A closed interval ends before another begins at the same version.
        return left.kind === "introduced" ? 1 : right.kind === "introduced" ? -1 : left.kind.localeCompare(right.kind);
      });
      let start: Semver | undefined;
      let open = false;
      for (const boundary of unique) {
        if (boundary.kind === "introduced") {
          if (open) return remediationUnavailable(pkg, installed, advisory, fixedVersions, "an affected interval is introduced before the preceding interval is closed");
          start = boundary.version;
          open = true;
          continue;
        }
        if (!open || !boundary.version) return remediationUnavailable(pkg, installed, advisory, fixedVersions, `a ${boundary.kind} boundary has no preceding introduced boundary`);
        intervals.push({ start, end: boundary.version, endInclusive: boundary.kind === "last_affected" });
        if (boundary.kind === "fixed") candidates.push(boundary.version);
        start = undefined;
        open = false;
      }
      if (open) intervals.push({ start, endInclusive: false });
      if (unique.length === 0) return remediationUnavailable(pkg, installed, advisory, fixedVersions, "an affected range has no interval events");
    }
  }

  if (!intervals.some((interval) => inInterval(current, interval)) && !explicitlyAffected.some((version) => compare(version, current) === 0)) {
    return remediationUnavailable(pkg, installed, advisory, fixedVersions, "the installed version does not fall in any SEMVER interval the parser can verify, despite the provider match");
  }
  const safe = candidates
    .filter((candidate) => compare(candidate, current) > 0 &&
      !intervals.some((interval) => inInterval(candidate, interval)) &&
      !explicitlyAffected.some((version) => compare(version, candidate) === 0))
    .sort(compare)[0];
  if (!safe) {
    return remediationUnavailable(pkg, installed, advisory, fixedVersions, fixedVersions.length === 0
      ? "no affected interval has a published fixed boundary"
      : "no published fixed boundary is newer than the installed version and outside every affected interval");
  }
  return {
    fixedVersions,
    fix: `Upgrade ${pkg} from ${installed} to ${safe.original}, a published fix outside every affected SEMVER interval in ${advisory}. Verify that the lockfile resolves ${safe.original} after updating.`,
  };
}
