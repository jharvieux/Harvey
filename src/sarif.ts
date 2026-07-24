// SARIF 2.1.0 export (#867) — Harvey's findings in the format GitHub code scanning and every
// ASPM platform (Checkmarx One, Cycode, OX, AccuKnox) already ingest. Hand-rolled: SARIF is
// plain JSON and a serializer is not worth a dependency.
//
// ── The coverage-ledger decision (the part that matters) ─────────────────────────────────────────
// SARIF has no concept of "this analysis was only partly performed". Left alone, a Harvey export
// would say "here are 12 results" and a platform would read that as the whole story — turning the
// deliverable's most important property (nine of ten modules did NOT run at the free tier) into
// silence. That is the exact inversion the coverage guard exists to prevent, so the ledger is
// carried in THREE places rather than dropped:
//
//   1. `runs[].invocations[0].toolExecutionNotifications` — one warning-level notification per
//      module that did not fully run, carrying its status and its reason. This is the standard,
//      machine-readable channel for "something about this run was incomplete" and is what a
//      SARIF-aware consumer should read.
//   2. `runs[].properties.harveyCoverage` — the ledger verbatim, for platforms that ignore
//      notifications but do surface property bags.
//   3. `tool.driver.notifications[]` — the descriptors, so the notifications are self-describing.
//
// `invocations[0].executionSuccessful` is deliberately left TRUE even when modules did not run.
// UNCERTAIN, flagged rather than asserted: GitHub code scanning is documented to treat a false
// value as a failed analysis, which would discard the results entirely — a not-in-scope tier is a
// scope fact, not a tool crash, and hiding real findings behind it would be a worse failure than
// the one we are guarding against. The loudness lives in the notifications instead.
//
// A caller cannot omit the ledger by accident: `toSarif` takes a discriminated union, so the only
// way to export without one is to state IN THE OUTPUT why there isn't one (`coverageAbsent`),
// which becomes its own warning notification. There is no silent path.

import { findingIdentity } from "./audit-diff.js";
import type { CoverageRow, Finding, Severity } from "./findings.js";
import { relativizeScanScope } from "./scan/scan-scope.js";

const SARIF_VERSION = "2.1.0";
const SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

type SarifLevel = "error" | "warning" | "note";

// Harvey severity → SARIF level. Perf/Info/Watch are observations, not defects; they stay in the
// export (dropping them would be the silent-omission failure) but at "note".
const LEVEL: Record<Severity, SarifLevel> = {
  Critical: "error",
  High: "error",
  Medium: "warning",
  Low: "note",
  Perf: "note",
  Info: "note",
  Watch: "note",
};

// GitHub code scanning ranks alerts by a numeric `security-severity` property on the RULE (a
// CVSS-like 0–10 string). Without it every Harvey alert lands in the same bucket and the ordering
// the report works hard to establish is lost on import.
const SECURITY_SEVERITY: Record<Severity, string> = {
  Critical: "9.5",
  High: "7.5",
  Medium: "5.0",
  Low: "3.0",
  Perf: "0.0",
  Info: "0.0",
  Watch: "0.0",
};

export interface SarifLocation {
  uri: string;
  startLine?: number;
  startColumn?: number;
  endLine?: number;
}

// Harvey locations are human-readable strings, not machine coordinates: "src/a.ts:42",
// "[source] .env:9", "package-lock.json (lodash@4.17.11)", "main DB (multiple tables)",
// "(repo-wide)". Only the ones that resolve to a real path get a physicalLocation; the rest are
// NOT dropped — see `nonFileLocations` in the export.
export function parseLocation(location: string): SarifLocation | undefined {
  const stripped = relativizeScanScope(location)
    // The mechanical scan runs over a temp copy of the target (src/scan/scan-scope.ts), so raw
    // findings carry that absolute prefix. Left in, every SARIF URI would point at a scratch dir
    // that no longer exists and would leak the operator's filesystem layout into a client artifact.
    .replace(/^\[[^\]]*\]\s*/, "") // tier prefix: "[source] "
    // Greedy to the LAST ")": descriptors nest, e.g. "…sql:44 (public.fn(arg))".
    .replace(/\s*\(.*\)\s*$/, "")
    .trim();
  if (!stripped) return undefined;

  const m = /^(\S+?):(\d+)(?::(\d+))?(?:-(\d+))?$/.exec(stripped);
  const uri = m ? m[1]! : stripped;
  // A path has no spaces and looks like a path or a file — "main DB" and "repo-wide" must not
  // become artifact URIs.
  if (/\s/.test(uri) || !/[/.]/.test(uri)) return undefined;

  if (!m) return { uri };
  return {
    uri,
    startLine: Number(m[2]),
    ...(m[3] ? { startColumn: Number(m[3]) } : {}),
    ...(m[4] ? { endLine: Number(m[4]) } : {}),
  };
}

function ruleIdOf(f: Finding): string {
  return f.taxonomy?.trim() || f.category?.trim() || "harvey/unclassified";
}

interface SarifRule {
  id: string;
  name?: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  help?: { text: string };
  defaultConfiguration: { level: SarifLevel };
  properties: { tags: string[]; "security-severity": string; category: string };
}

interface SarifNotification {
  descriptor: { id: string };
  level: SarifLevel;
  message: { text: string };
  properties?: Record<string, unknown>;
}

export type CoverageInput = { coverage: CoverageRow[] } | { coverageAbsent: string };

export interface SarifOptions {
  toolVersion?: string;
  // Absolute-path prefix stripped from artifact URIs so they are repo-relative, which is what
  // GitHub code scanning needs to attach an alert to a file.
  baseUri?: string;
}

const NOTIFICATION_DESCRIPTORS = [
  { id: "harvey/coverage/not-run", shortDescription: { text: "An audit module did not fully run; its findings are absent from this export by definition, not because the module was clean." } },
  { id: "harvey/coverage/absent", shortDescription: { text: "This export carries no per-module coverage ledger; the scope it covers is stated in the message." } },
  { id: "harvey/location/non-file", shortDescription: { text: "Some findings describe a non-file location (a database object, a repo-wide condition) that cannot be expressed as a SARIF file region." } },
];

function coverageNotifications(input: CoverageInput): SarifNotification[] {
  if ("coverageAbsent" in input) {
    return [{
      descriptor: { id: "harvey/coverage/absent" },
      level: "warning",
      message: { text: `No per-module coverage ledger accompanies this export. ${input.coverageAbsent}` },
    }];
  }
  const gaps = input.coverage.filter((r) => r.status !== "ran");
  if (gaps.length === 0) return [];
  return gaps.map((row) => ({
    descriptor: { id: "harvey/coverage/not-run" },
    level: "warning" as const,
    message: {
      text: `${row.module} (${row.name})${row.instance ? ` [${row.instance}]` : ""}: ${row.status} — ${row.reason ?? "no reason recorded"}. ` +
        "An absent finding from this module means it was not assessed, not that it is clean.",
    },
    properties: { module: row.module, status: row.status, ...(row.instance ? { instance: row.instance } : {}) },
  }));
}

export function toSarif(findings: Finding[], coverage: CoverageInput, opts: SarifOptions = {}): object {
  const rules = new Map<string, SarifRule>();
  const nonFileLocations: string[] = [];

  const results = findings.map((f) => {
    const ruleId = ruleIdOf(f);
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: ruleId,
        shortDescription: { text: f.title },
        ...(f.impact ? { fullDescription: { text: f.impact } } : {}),
        ...(f.fix ? { help: { text: f.fix } } : {}),
        defaultConfiguration: { level: LEVEL[f.severity] },
        properties: {
          tags: [f.category, ...(f.cwe ?? []), ...(f.owasp ?? [])].filter(Boolean),
          "security-severity": SECURITY_SEVERITY[f.severity],
          category: f.category,
        },
      });
    }

    const parsed = parseLocation(f.location);
    if (!parsed) nonFileLocations.push(f.location);
    const uri = parsed && opts.baseUri && parsed.uri.startsWith(opts.baseUri)
      ? parsed.uri.slice(opts.baseUri.length).replace(/^\/+/, "")
      : parsed?.uri;

    return {
      ruleId,
      level: LEVEL[f.severity],
      // The location string is repeated in the message so a finding whose location cannot be a
      // file region still says where it is, rather than reading as an unlocated repo-wide alert.
      message: { text: `${f.title} — ${f.location}${f.evidence ? `\n\n${f.evidence}` : ""}` },
      ...(parsed
        ? {
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: uri! },
                ...(parsed.startLine
                  ? { region: { startLine: parsed.startLine, ...(parsed.startColumn ? { startColumn: parsed.startColumn } : {}), ...(parsed.endLine ? { endLine: parsed.endLine } : {}) } }
                  : {}),
              },
            }],
          }
        : {}),
      partialFingerprints: { "harveyFindingIdentity/v1": findingIdentity(f) },
      properties: {
        harveyId: f.id,
        severity: f.severity,
        confidence: f.confidence,
        location: f.location,
        ...(f.precisionTier ? { precisionTier: f.precisionTier } : {}),
        ...(f.baselineStatus ? { baselineStatus: f.baselineStatus } : {}),
        ...(f.exploitabilityVerified ? { exploitabilityVerified: true } : {}),
      },
    };
  });

  const notifications = coverageNotifications(coverage);
  if (nonFileLocations.length > 0) {
    notifications.push({
      descriptor: { id: "harvey/location/non-file" },
      level: "warning",
      message: {
        text: `${nonFileLocations.length} finding(s) have a location that is not a file region ` +
          `(e.g. ${[...new Set(nonFileLocations)].slice(0, 3).join(", ")}). They are exported as results with no ` +
          "physicalLocation; their location is in the result message and in properties.location.",
      },
    });
  }

  return {
    $schema: SCHEMA,
    version: SARIF_VERSION,
    runs: [{
      tool: {
        driver: {
          name: "Harvey",
          informationUri: "https://github.com/jharvieux/Harvey",
          ...(opts.toolVersion ? { version: opts.toolVersion } : {}),
          rules: [...rules.values()],
          notifications: NOTIFICATION_DESCRIPTORS,
        },
      },
      invocations: [{
        // See the header: true even with gaps. The gaps are the notifications below.
        executionSuccessful: true,
        toolExecutionNotifications: notifications,
      }],
      results,
      properties: "coverage" in coverage
        ? { harveyCoverage: coverage.coverage }
        : { harveyCoverageAbsent: coverage.coverageAbsent },
    }],
  };
}
