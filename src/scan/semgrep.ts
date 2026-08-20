// Next.js/web footguns via Semgrep OSS: dangerouslySetInnerHTML, permissive CORS,
// service-role-in-client, open redirects, injection family (custom rules — the directory
// src/scan/rules/semgrep/, one file per security batch) layered on the registry security packs.
//
// Semgrep is an external CLI binary, not an npm dependency. Install: `pip install semgrep`
// or `brew install semgrep` (https://semgrep.dev/docs/getting-started/). `--config p/*`
// packs are fetched from the Semgrep registry over the network on first run (cached after).
//
// Invocation (maintained registry packs from mechanical-toolchain.md §2 + our custom rules):
//   semgrep --config p/typescript --config p/react --config p/nextjs --config p/owasp-top-ten \
//     --config p/secrets --config p/security-audit \
//     --config src/scan/rules/semgrep/ --exclude node_modules --json <dir>
//
// Trust boundary: severity ERROR + metadata.confidence HIGH + not a `.audit.`-suffixed rule
// is "high" precision (docs/design/mechanical-toolchain.md §2/§7) — the free count; everything
// else (MEDIUM/LOW confidence, WARNING/INFO, `.audit.*`) is "review" tier.
//
// Missing CSP is checked separately below (checkMissingCsp) — it's a config-presence check
// across next.config/middleware/vercel.json, not something a Semgrep AST pattern expresses.

import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";
import { readEntriesSafe, readNamesSafe, statSafe } from "../fs-walk.js";
import type { Finding, Severity } from "../findings.js";
import { mechanicalFinding } from "./common.js";
import { PLATFORM_HEADER_IMPACT_SUFFIX, platformHeaderTrusted } from "./header-trust.js";
import {
  assertSemgrepFamilyPlan,
  assertSemgrepFamilyVerification,
  discoverLocalSemgrepFamilies,
  executeSemgrepFamily,
  mergeSemgrepFamilyOutputs,
  localSemgrepConfigYardstick,
  rejectUnregisteredSemgrepFamilyArtifacts,
  type SemgrepFamily,
  type SemgrepFamilyCacheOptions,
  type SemgrepFamilyRecord,
} from "./semgrep-family-cache.js";


// The whole custom-rule directory is loaded as one --config; each security batch adds its own
// `<batch>.yml` here (no shared file → conflict-free parallel batches).
const CUSTOM_RULES = new URL("./rules/semgrep/", import.meta.url).pathname;

// The maintained registry packs every real engagement scan fetches (runSemgrep below) — shared with
// runRegistryPacksOnFile's single-file replay (#1368) so the two can never drift apart.
export const REGISTRY_PACKS = ["p/typescript", "p/react", "p/nextjs", "p/owasp-top-ten", "p/secrets", "p/security-audit"] as const;
const materializedRegistryMemo = new Map<string, { identity?: string; files?: string[]; failure?: string }>();

interface RegistryPackSnapshotManifest {
  schema: 1;
  identity: string;
}

export function registryPackIdentity(bodies: readonly { pack: string; body: string }[]): string {
  const hash = createHash("sha256");
  for (const { pack, body } of bodies) {
    hash.update(pack);
    hash.update("\0");
    hash.update(body);
  }
  return hash.digest("hex");
}

function registryPackFiles(cacheDir: string, identity: string): string[] {
  const dir = join(cacheDir, "registry-packs", identity);
  return REGISTRY_PACKS.map((pack, index) => join(dir, `${index}-${pack.replaceAll("/", "-")}.yml`));
}

function readRestoredRegistrySnapshot(cacheDir: string): { identity?: string; files?: string[]; failure?: string } {
  const manifestPath = join(cacheDir, "registry-packs", "current.json");
  try {
    if (!existsSync(manifestPath)) throw new Error("current.json is missing");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Partial<RegistryPackSnapshotManifest>;
    if (manifest.schema !== 1 || typeof manifest.identity !== "string" || !/^[a-f0-9]{64}$/.test(manifest.identity)) {
      throw new Error("current.json has an invalid schema or identity");
    }
    const files = registryPackFiles(cacheDir, manifest.identity);
    const bodies = files.map((path, index) => {
      if (!existsSync(path)) throw new Error(`${relative(cacheDir, path)} is missing`);
      return { pack: REGISTRY_PACKS[index]!, body: readFileSync(path, "utf8") };
    });
    const actual = registryPackIdentity(bodies);
    if (actual !== manifest.identity) throw new Error(`snapshot bytes hash to ${actual}, not ${manifest.identity}`);
    return { identity: actual, files };
  } catch (error) {
    return { failure: `restored Semgrep registry snapshot required on CI retry but is invalid: ${error instanceof Error ? error.message : String(error)}` };
  }
}

export function materializeRegistryPacks(cacheDir: string, mode: "refresh" | "reuse" = "refresh"): { identity?: string; files?: string[]; failure?: string } {
  const memoKey = `${mode}:${cacheDir}`;
  const memo = materializedRegistryMemo.get(memoKey);
  if (memo) return memo;
  if (mode === "reuse") {
    const result = readRestoredRegistrySnapshot(cacheDir);
    materializedRegistryMemo.set(memoKey, result);
    return result;
  }
  const bodies: { pack: string; body: string }[] = [];
  try {
    for (const pack of REGISTRY_PACKS) {
      const config = execFileSync("curl", ["-fsSL", `https://semgrep.dev/c/${pack}`], {
        encoding: "utf8",
        maxBuffer: 1024 * 1024 * 32,
        timeout: 60_000,
      });
      bodies.push({ pack, body: config });
    }
    const identity = registryPackIdentity(bodies);
    const dir = join(cacheDir, "registry-packs", identity);
    mkdirSync(dir, { recursive: true });
    const files = bodies.map(({ pack, body }, index) => {
      const path = join(dir, `${index}-${pack.replaceAll("/", "-")}.yml`);
      if (!existsSync(path) || readFileSync(path, "utf8") !== body) {
        const temp = `${path}.${process.pid}.tmp`;
        writeFileSync(temp, body);
        renameSync(temp, path);
      }
      return path;
    });
    const manifestPath = join(cacheDir, "registry-packs", "current.json");
    const manifestTemp = `${manifestPath}.${process.pid}.tmp`;
    writeFileSync(manifestTemp, `${JSON.stringify({ schema: 1, identity } satisfies RegistryPackSnapshotManifest, null, 2)}\n`);
    renameSync(manifestTemp, manifestPath);
    const result = { identity, files };
    materializedRegistryMemo.set(memoKey, result);
    return result;
  } catch (error) {
    const e = error as { code?: string; message?: string };
    const result = { failure: e.code === "ENOENT" ? "curl not found while materializing Semgrep registry packs" : `Semgrep registry packs could not be reproducibly materialized: ${e.message ?? "registry fetch failed"}` };
    materializedRegistryMemo.set(memoKey, result);
    return result;
  }
}

export interface SemgrepResult {
  check_id: string;
  path: string;
  start?: { line?: number };
  // #1093: partitionGuardTokenSuppressed reads [start.line, end.line] to re-scan the whole matched
  // function span, so it needs the match's end, not just its start.
  end?: { line?: number };
  extra?: {
    message?: string;
    severity?: string; // legacy ERROR|WARNING|INFO or new CRITICAL|HIGH|MEDIUM|LOW (#1166)
    // cwe/owasp (#455): carried by both the registry p/owasp-top-ten pack and, where added, our
    // harvey-* custom rules — see each rule's `metadata:` block in ./rules/semgrep/*.yml. A registry
    // rule may declare `cwe`/`owasp` as a bare STRING rather than a list, so the type admits both and
    // `strList` below normalizes it (a string reached downstream `.cwe.map()` and threw — #975/#976).
    // harveyTaxonomy (#996): a rule's canonical taxonomy override — how a rule that stays exact
    // about the FACT (ERROR + HIGH → free report) declares itself non-grading: the string is keyed
    // in NON_GRADING_TAXONOMIES (src/quick-scan.ts), the same routing the doc-context credential
    // reclassification (#934) uses. Also stable across environments, unlike the path-prefixed
    // check_id the taxonomy otherwise carries.
    // #1077: references/likelihood/impact/source are the rule's own remediation metadata — MEASURED
    // 2026-07-25 (semgrep 1.164.0) on all six registry packs Harvey loads: 915/915 rules carry
    // `references`, 638 carry likelihood+impact. Dropping these left 224/386 (58%) of a real
    // deliverable's findings carrying an identical placeholder fix string one line after the rule's
    // own guidance was discarded.
    metadata?: {
      confidence?: string;
      harveySeverity?: string;
      harveyTaxonomy?: string;
      cwe?: string[] | string;
      owasp?: string[] | string;
      references?: string[] | string;
      likelihood?: string;
      impact?: string;
      source?: string;
    };
  };
}

export interface SemgrepOutput {
  results?: SemgrepResult[];
  // Per-path problems semgrep reports WITHOUT failing the run (a syntax error in one file, an
  // unreadable scanning root). Empty results next to an error on the scanned path means the rules
  // never evaluated that file — load-bearing for the fix pipeline's re-run (#1012), which must not
  // read "no match" off a file semgrep could not parse. #1077: `type` is a bare string for a
  // whole-file syntax error (MEASURED 2026-07-25) but semgrep also emits it as an array (e.g.
  // ["PartialParsing", [...]]) for a partial-parse warning — typed to admit both rather than assume.
  errors?: { type?: string | unknown[]; message?: string; path?: string }[];
  // Absolute paths semgrep actually analysed. #1021 — the single-file re-run narrows a rooted scan
  // with --include, and a narrowing that matched nothing is indistinguishable from a clean file
  // unless this is read. #1077: `skipped` (files semgrep chose not to analyse — size limit,
  // semgrepignore, minified) is only populated at `--verbose`; runSemgrep now passes it instead of
  // `--quiet` (mutually exclusive) so this is never silently empty.
  paths?: { scanned?: string[]; skipped?: { path?: string; reason?: string }[] };
  // #1368: `--time`'s exhaustive list of rule ids semgrep actually loaded and considered for the
  // scan, present regardless of match. This is the only offline-unavailable way to tell "a registry
  // rule id that was evaluated and found nothing" from "not a rule id this scan ever ran at all" —
  // registry packs carry no local file a re-run can read the id list from the way harvey-* rules do.
  time?: { rules?: string[] };
}

export interface SemgrepExecutionPlanReceipt {
  schema: 4;
  strategy: "partitioned-families";
  families: Array<{
    ordinal: number;
    id: string;
    configSha256: string;
    argv: string[];
    verification: "single" | "rule-partition-exact";
    subpartitions?: Array<{
      id: string;
      includedRuleIds: string[];
      excludedRuleIds: string[];
      excludedTargetPaths: string[];
      target: string;
      argv: string[];
    }>;
  }>;
}

// #1166: semgrep 1.164 emits its NEW 4-level taxonomy (CRITICAL/HIGH/MEDIUM/LOW) alongside the
// legacy 3-level one (ERROR/WARNING/INFO) — MEASURED 2026-07-26 (semgrep 1.164.0): a live six-pack
// scan produced MEDIUM as an `extra.severity` string (e.g. npm-missing-minimum-release-age). Mapping
// only the legacy three meant a HIGH/CRITICAL registry rule with no harveySeverity override fell to
// the old `?? "Medium"` default — a real Critical shipped Medium (the #1063 mis-rating class at the
// semgrep→Finding severity seam). Both taxonomies are mapped; an unrecognised string FAILS LOUD
// (severityFromSemgrep throws) rather than vanishing into a silent default.
const SEVERITY_FROM_SEMGREP: Record<string, Severity> = {
  ERROR: "High",
  WARNING: "Medium",
  INFO: "Low",
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
};

function severityFromSemgrep(raw: string | undefined): Severity {
  const key = raw ?? "WARNING";
  const mapped = SEVERITY_FROM_SEMGREP[key];
  if (mapped === undefined) {
    throw new Error(
      `Unmapped semgrep severity "${key}" — semgrep may have changed its severity taxonomy; ` +
        `add it to SEVERITY_FROM_SEMGREP (src/scan/semgrep.ts, #1166) rather than let it default to Medium.`,
    );
  }
  return mapped;
}

// #996: canonical taxonomies for the two demoted-to-informational rules. Each is declared as
// metadata.harveyTaxonomy on its rule (base.yml harvey-permissive-cors-bare, xss.yml
// harvey-postmessage-wildcard) — semgrep.test.ts pins the YAML strings to these constants —
// and keyed in NON_GRADING_TAXONOMIES (src/quick-scan.ts): reported in full, never graded.
export const CORS_BARE_WILDCARD_TAXONOMY = "Permissive CORS — wildcard without credentials (confirm intent)";
export const POSTMESSAGE_WILDCARD_TAXONOMY = "postMessage to any origin — a leak only if the data is sensitive (confirm)";

// #996 (operator decision, mirroring the Dependency-CVE mechanism): findings in GitHub Actions
// workflow files are real and fully reported — never "not assessed" — but they grade CI/CD
// pipeline hygiene, not the application's code, and their exploitability hinges on repository/
// trigger settings the scan cannot see (who can open PRs, which events fire the workflow). They
// land in their own category, keyed in NON_GRADING_CATEGORIES (src/quick-scan.ts), rendered as a
// distinct section of the free report. CI config is deliberately NOT part of the #903
// infrastructure not-assessed disclosure: Harvey DID assess these files and found things.
export const CI_PIPELINE_CATEGORY = "CI/CD pipeline hygiene";
const CI_WORKFLOW_PATH = /(^|\/)\.github\/workflows\//;
const CI_PIPELINE_IMPACT_SUFFIX =
  " Reported in full as CI/CD pipeline hygiene, outside the app-hygiene grade: exploitability " +
  "depends on repository and workflow-trigger settings this scan cannot see.";

function isAuditRule(checkId: string): boolean {
  return checkId.includes(".audit.") || checkId.endsWith(".audit");
}

// A semgrep rule's metadata.cwe/owasp is usually a list but some registry rules declare a bare
// string; normalize to a non-empty string[] (or undefined) so a finding's cwe/owasp is always an array.
function strList(v: string[] | string | undefined): string[] | undefined {
  if (Array.isArray(v)) return v.length ? v : undefined;
  return v ? [v] : undefined;
}

const GENERIC_FIX = "Review the matched code path against the rule's remediation guidance.";

// #1077: compose the fix from the rule's OWN remediation links when it declared any — the generic
// placeholder was showing on 224/386 (58%) of a real deliverable's findings one line after this
// exact metadata was discarded. Falls back to the placeholder only when the rule (e.g. every one of
// Harvey's own harvey-* custom rules today, MEASURED 2026-07-25) declares no references/source.
function composeFix(references: string[] | undefined, source: string | undefined): string {
  const links = [...(references ?? []), ...(source ? [source] : [])];
  if (links.length === 0) return GENERIC_FIX;
  return `Review the matched code path against the rule's remediation guidance: ${links.join(", ")}.`;
}

export function parseSemgrepFindings(output: SemgrepOutput): Finding[] {
  const results = output.results ?? [];
  // #1295: #984's unbuilt half — a free-count tier that rests entirely on trusting a platform-set
  // header lands at review tier instead, with the routing reason stated on the finding.
  const headerRouted = platformHeaderTrusted(results);
  return results.map((r, i) => {
    const meta = r.extra?.metadata;
    const severity = (meta?.harveySeverity as Severity | undefined) ?? severityFromSemgrep(r.extra?.severity);
    const trustedHeader = headerRouted.has(r);
    const high =
      r.extra?.severity === "ERROR" && meta?.confidence === "HIGH" && !isAuditRule(r.check_id) && !trustedHeader;
    const message = r.extra?.message?.trim().split("\n")[0] ?? "Semgrep match";
    // #996: a workflow-file finding is a fact about the CI pipeline, not the app — its own
    // fully-reported non-grading category, with the routing reason stated on the finding.
    const ciWorkflow = CI_WORKFLOW_PATH.test(r.path);
    const base = r.extra?.message ?? "See the rule's message for the specific risk.";
    const impact = trustedHeader ? base + PLATFORM_HEADER_IMPACT_SUFFIX : base;
    const references = strList(meta?.references);
    return mechanicalFinding({
      id: `SEM-${i + 1}`,
      title: `${r.check_id}: ${message}`,
      severity,
      category: ciWorkflow ? CI_PIPELINE_CATEGORY : "Next.js/web footgun",
      taxonomy: meta?.harveyTaxonomy ?? r.check_id,
      location: `${r.path}${r.start?.line ? `:${r.start.line}` : ""}`,
      evidence: r.extra?.message ?? `Semgrep rule ${r.check_id} matched.`,
      impact: ciWorkflow ? impact + CI_PIPELINE_IMPACT_SUFFIX : impact,
      fix: composeFix(references, meta?.source),
      precisionTier: high ? "high" : "review",
      // #455 — populate only from the rule's own declared metadata, never invented here.
      cwe: strList(meta?.cwe),
      owasp: strList(meta?.owasp),
      references,
    });
  });
}

// CSP presence check across the places a Next app can set it: next.config.{js,mjs,ts},
// middleware.{ts,js} (also under src/), and vercel.json. Flags when a Next config exists but
// none of them declares a Content-Security-Policy. Always "review" tier — CSP can legitimately
// be set at the CDN/hosting layer this repo scan can't see.
const CSP_CONFIG_FILES = [
  "next.config.js", "next.config.mjs", "next.config.ts",
  "middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js",
  "vercel.json",
];

export function checkMissingCsp(dir: string): Finding[] {
  const present = CSP_CONFIG_FILES.map((f) => join(dir, f)).filter(existsSync);
  if (present.length === 0) return [];
  const hasCsp = present.some((p) => /content-security-policy/i.test(readFileSync(p, "utf8")));
  if (hasCsp) return [];
  return [
    mechanicalFinding({
      id: "SEM-CSP-1",
      title: "No Content-Security-Policy configured",
      severity: "Medium",
      category: "Next.js/web footgun",
      taxonomy: "Missing security headers",
      location: present[0]!.slice(dir.length + 1),
      evidence: `No Content-Security-Policy found in ${present.map((p) => p.slice(dir.length + 1)).join(", ")}.`,
      impact: "No CSP leaves XSS sinks (e.g. dangerouslySetInnerHTML) without a defense-in-depth mitigation.",
      fix: "Add a Content-Security-Policy header (in next.config headers(), middleware, or the hosting platform config).",
      precisionTier: "review",
    }),
  ];
}

// Sensitive files served from the public/ directory (B12, #71). Next.js serves everything under
// public/ verbatim at the site root, so a committed .env / DB dump / private key / backup there is
// world-readable — a config/secret leak a Semgrep AST rule can't express (it's a filesystem-presence
// fact, not a code pattern). Fires `high`: the file is unambiguously sensitive AND unambiguously
// web-served. Benign assets (favicon, fonts, images, robots.txt, manifests) don't match.
const PUBLIC_SENSITIVE = [
  /^\.env(\.|$)/i, // .env, .env.local, .env.production, ...
  /\.(sql|pem|key|bak|sqlite|sqlite3|db|p12|pfx|keystore|kdbx)$/i,
  /^(backup|dump|database|db[-_]?dump)\b/i,
  /^id_(rsa|ed25519|ecdsa|dsa)$/i,
  /\.(env|secrets?)\.(json|ya?ml)$/i,
];

function walkFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readEntriesSafe(dir).entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory) out.push(...walkFiles(full));
    else out.push(full);
  }
  return out;
}

export function checkPublicDirSensitive(dir: string): Finding[] {
  const publicDir = join(dir, "public");
  if (!existsSync(publicDir)) return [];
  const findings: Finding[] = [];
  for (const file of walkFiles(publicDir)) {
    const base = file.slice(file.lastIndexOf("/") + 1);
    if (!PUBLIC_SENSITIVE.some((re) => re.test(base))) continue;
    const rel = relative(dir, file);
    findings.push(
      mechanicalFinding({
        id: `SEM-PUBLIC-${findings.length + 1}`,
        title: `Sensitive file served from public/: ${rel}`,
        severity: "High",
        category: "Next.js/web footgun",
        taxonomy: "Sensitive file in public/ directory",
        location: rel,
        evidence: `${rel} sits under public/, which Next.js serves verbatim at /${rel.replace(/^public\//, "")}.`,
        impact: "Anyone can download this file over the web — it may expose credentials, database contents, or private keys.",
        fix: "Move the file out of public/ (into a server-only location or .gitignore), and rotate any secret it exposed.",
        precisionTier: "high",
      }),
    );
  }
  return findings;
}

// #950: mirrors the osv-scanner pattern (#512, src/scan/dependencies.ts) — a missing/crashing
// semgrep binary must degrade to a disclosed coverage gap, never an uncaught ENOENT that hard-
// exits the whole quick-scan CLI. `failure` set ⇒ the caller substitutes semgrepUnavailableFinding.
//
// #1066 — the two scope flags are an AUDIT-INTEGRITY requirement, not a tuning knob. Without them
// the audited party controls what Harvey sees (MEASURED 2026-07-25, semgrep 1.164.0):
//   --disable-nosem                 a bare `// nosemgrep` above a sink removed the finding while
//                                   the file still appeared in paths.scanned — scanned-and-clean.
//                                   Harvey re-applies the marker itself (partitionMarkerSuppressed)
//                                   so every suppressed match is COUNTED in SEM-SUPPRESS-00.
//   --x-ignore-semgrepignore-files  a committed .semgrepignore travels into the scan copy with the
//                                   rest of the git-tracked files (scan-scope.ts) and applied;
//                                   semgrep's BUILT-IN default set also dropped tests/, test/,
//                                   vendor/, dist/, build/ — 5 of 8 probed directories, vendor/
//                                   being real shipped code. With the flag: 8 of 8 scanned.
// The flag is marked [INTERNAL] by semgrep, so a version that drops it would otherwise take the
// whole footgun scan down; fall back to a run without it. That degradation is not silent — the
// files it re-drops then show up in SEM-SCOPE-00, which is derived from paths.scanned, not from
// which flags we passed.
// #1664: whether a non-zero exit can be benign — MEASURED 2026-07-31, semgrep 1.164.0. A COMPLETED
// run of these invocations exits 0 in every benign case probed: findings are non-blocking without
// `--error` (392 findings → exit 0), and a per-file syntax error exits 0 with an `errors[]` entry at
// level "warn". The incomplete runs all exit non-zero or die on a signal: `--config /dev/null`
// exits 7 with a valid empty envelope (results: [], errors[] at level "error"); killing semgrep-core
// with SIGBUS once is survived (respawn, exit 0, a genuinely complete scan); killing every respawn
// makes the wrapper exit 2 with stdout `<ERROR: missing output>` — non-empty but NOT JSON. The
// previous shape of this catch treated ANY non-empty stdout as success, so a crashed run's
// empty/partial envelope scored as a CLEAN scan — the live `semgrep-core exited with -10!` crash
// behind #1664 made validate-calibration read "113 rules have never been shown to work" off a scan
// that never ran. There is no benign non-zero exit to spare, so every one is INCOMPLETE, named by
// its observed exit code or signal.
// #1756: exported for `src/cli/validate-secbench.ts`, which invoked semgrep raw with the pre-#1664
// swallow — copy-pasting the classifier is how the two drift apart. `maxBufferMb` is a parameter for
// the same reason: that gate scans ~600 SecBench entries in one pass and had already raised its own
// cap to 256 MB, and silently halving it here would turn a working run into a disclosed failure.
type SemgrepExec = { out: string } | { failure: string; enoent: boolean };

interface SemgrepExecError {
  stdout?: string;
  code?: string | number;
  status?: number | null;
  signal?: string | null;
}

function semgrepFailure(err: SemgrepExecError): SemgrepExec {
  if (err.code === "ENOENT") return { failure: "semgrep not found on PATH", enoent: true };
  const status = err.status ?? (typeof err.code === "number" ? err.code : undefined);
  const how = err.signal ? `killed by signal ${err.signal}` : `exited with code ${status ?? "unknown"}`;
  return { failure: `semgrep run did not complete (${how})${envelopeErrorSummary(err.stdout)}`, enoent: false };
}

let liveAsyncSemgrepCommands = 0;
let peakAsyncSemgrepCommands = 0;
export const observedSemgrepCommandConcurrency = (): number => peakAsyncSemgrepCommands;

export function execSemgrep(argv: string[], maxBufferMb = 128): SemgrepExec {
  try {
    return { out: execFileSync("semgrep", argv, { encoding: "utf8", maxBuffer: 1024 * 1024 * maxBufferMb }) };
  } catch (err) {
    return semgrepFailure(err as SemgrepExecError);
  }
}

function execSemgrepAsync(argv: string[], maxBufferMb = 128): Promise<SemgrepExec> {
  liveAsyncSemgrepCommands++;
  peakAsyncSemgrepCommands = Math.max(peakAsyncSemgrepCommands, liveAsyncSemgrepCommands);
  return new Promise((resolve) => {
    execFile("semgrep", argv, { encoding: "utf8", maxBuffer: 1024 * 1024 * maxBufferMb }, (err, stdout) => {
      liveAsyncSemgrepCommands--;
      if (err) {
        resolve(semgrepFailure({ ...(err as SemgrepExecError), stdout }));
        return;
      }
      resolve({ out: stdout });
    });
  });
}

// The crash's own explanation, when the wrapper still emitted its JSON envelope on the way down
// (the exit-7 shape carries "invalid configuration file found" there; the SIGBUS shape emits no
// JSON at all, so a parse failure here is expected, not exceptional).
function envelopeErrorSummary(stdout: string | undefined): string {
  if (!stdout) return "";
  try {
    const errors = (JSON.parse(stdout) as SemgrepOutput).errors ?? [];
    const msgs = errors.map((e) => e.message?.trim().split("\n")[0]).filter(Boolean).slice(0, 3);
    return msgs.length ? `: ${msgs.join("; ")}` : "";
  } catch {
    return "";
  }
}

function parseEnvelope(out: string): { result: SemgrepOutput; failure?: string } {
  try {
    return { result: JSON.parse(out) as SemgrepOutput };
  } catch {
    // Measured adjacent shape (#1664): a crashed run can leave literal `<ERROR: missing output>` on
    // stdout (observed at exit 2, not at exit 0). Whatever the exit, unparseable scanner output
    // degrades to a disclosed failure rather than an uncaught SyntaxError or a false clean.
    return { result: {}, failure: "semgrep exited 0 but printed something other than its JSON envelope — treated as an incomplete run, never as a clean scan" };
  }
}

// #1710 — the invocation is PINNED for determinism and recall, because semgrep 1.164.0's default
// mode silently loses findings. MEASURED 2026-07-31 (semgrep 1.164.0, the version
// .github/actions/mechanical-binaries pins — full tables in docs/design/semgrep-determinism.md):
//   * default (shared-memory threads, -j 9, --timeout 5): EVERY one of 10 full scans of the pinned
//     carbon tree was missing 17-29 of the 530 findings the single-threaded run produces — all
//     taint-mode rows (harvey-log-injection, harvey-unchecked-mutation) on 1500+-line files, and
//     most of the losses left NO trace in errors[], paths.skipped or stderr. Not jitter around a
//     mean: a silent recall loss. The 5s per-rule-per-file timeout adds a second, load-dependent
//     loss mode on top (which rules cross 5s varies run to run; those ARE recorded in errors[]).
//   * Nine-worker parmap remains the measured fast topology for every family except local-injection.
//     Two separate hosted producer/replay runs later falsified it for that family: each silently
//     omitted one different harvey-log-injection row from the same exact Carbon bytes while the
//     Semgrep diagnostics stayed equal. Two local j9 repeats happened to agree, so a j9 replay is
//     not itself a sufficient guard.
//   * Repeating the same whole-family j1 shape twice was later falsified too: two independent
//     hosted pairs each agreed internally but settled on different 532/533-row modes. Even a
//     single large Carbon file settled on different 2/5-row modes when all 30 injection rules ran
//     together. The unstable harvey-log-injection rule is therefore executed alone over bounded
//     inputs: every targetable JS/TS file above 80 KiB once, then the exact remainder with those
//     paths excluded. The source-derived 29-rule complement executes once over the whole target.
//     Two complete cold 22-invocation Carbon partitions were byte-identical and conserved all 87
//     findings, 4,152 scanned paths, and 30 rules against the monolithic family. The merge retains
//     the 20 explicit exclusion receipts; it does not suppress or normalize them.
//   * `-j 1` without parmap is not the measured alternative and is not a safe fallback: 1 of 3
//     historical runs dropped a row. Because
//     --x-parmap is internal, a future Semgrep that rejects it must disclose SEM-00/incomplete
//     coverage rather than silently switch to an unproved execution engine.
// Stability remains a falsifiable corpus property, not something these flags prove by themselves.
const SEMGREP_PINNED_PREFIX = ["--x-ignore-semgrepignore-files", "--x-parmap", "-j", "9"] as const;
const SEMGREP_VERIFIED_PREFIX = ["--x-ignore-semgrepignore-files", "--x-parmap", "-j", "1"] as const;
const SEMGREP_PAIRED_FAMILY = "local-injection";
const SEMGREP_ISOLATED_RULE = "harvey-log-injection";
const SEMGREP_LARGE_SOURCE_BYTES = 80 * 1024;
const SEMGREP_DEFAULT_MAX_TARGET_BYTES = 1_000_000;
const SEMGREP_TARGETABLE_SOURCE_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]);
const SEMGREP_IGNORED_DISCOVERY_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage"]);

function semgrepFamilyPolicy(family: SemgrepFamily): {
  prefix: readonly string[];
  verification: "single" | "rule-partition-exact";
} {
  return family.id === SEMGREP_PAIRED_FAMILY
    ? { prefix: SEMGREP_VERIFIED_PREFIX, verification: "rule-partition-exact" }
    : { prefix: SEMGREP_PINNED_PREFIX, verification: "single" };
}

function familyRuleIds(configPath: string): string[] {
  const ids = [...readFileSync(configPath, "utf8").matchAll(/^\s*-\s*id:\s*([\w-]+)\s*$/gm)].map((match) => match[1]!);
  if (ids.length === 0) throw new Error(`Semgrep family ${configPath} declares no rule ids`);
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
  if (duplicates.length > 0) throw new Error(`Semgrep family ${configPath} declares duplicate rule ids: ${[...new Set(duplicates)].sort().join(", ")}`);
  return [...ids].sort();
}

interface SemgrepRuleSubpartition {
  id: string;
  includedRuleIds: string[];
  excludedRuleIds: string[];
  excludedTargetPaths: string[];
  target: string;
}

function largeTargetableSourcePaths(dir: string, current: string = dir, out: string[] = []): string[] {
  for (const entry of readEntriesSafe(current).entries) {
    if (entry.isDirectory) {
      if (!SEMGREP_IGNORED_DISCOVERY_DIRS.has(entry.name)) largeTargetableSourcePaths(dir, entry.path, out);
      continue;
    }
    if (!SEMGREP_TARGETABLE_SOURCE_EXTENSIONS.has(extname(entry.name).toLowerCase())) continue;
    const stat = statSafe(entry.path);
    if (!stat?.isFile()) continue;
    if (stat.size > SEMGREP_LARGE_SOURCE_BYTES && stat.size < SEMGREP_DEFAULT_MAX_TARGET_BYTES) {
      out.push(relative(dir, entry.path).replaceAll("\\", "/"));
    }
  }
  return out.sort();
}

function injectionRuleSubpartitions(family: SemgrepFamily, dir: string): SemgrepRuleSubpartition[] {
  const all = familyRuleIds(family.configPath);
  const isolatedCount = all.filter((id) => id === SEMGREP_ISOLATED_RULE).length;
  if (isolatedCount !== 1) {
    throw new Error(`Semgrep family ${family.configPath} must declare ${SEMGREP_ISOLATED_RULE} exactly once; found ${isolatedCount}`);
  }
  const complement = all.filter((id) => id !== SEMGREP_ISOLATED_RULE);
  if (complement.length === 0) throw new Error(`Semgrep family ${family.configPath} has no complement beside ${SEMGREP_ISOLATED_RULE}`);
  const large = largeTargetableSourcePaths(dir);
  const partitions: SemgrepRuleSubpartition[] = [
    {
      id: "isolated-log-injection/remainder",
      includedRuleIds: [SEMGREP_ISOLATED_RULE],
      excludedRuleIds: complement,
      excludedTargetPaths: large,
      target: dir,
    },
    ...large.map((path, ordinal) => ({
      id: `isolated-log-injection/file-${String(ordinal + 1).padStart(3, "0")}`,
      includedRuleIds: [SEMGREP_ISOLATED_RULE],
      excludedRuleIds: complement,
      excludedTargetPaths: [],
      target: join(dir, path),
    })),
    {
      id: "complement",
      includedRuleIds: complement,
      excludedRuleIds: [SEMGREP_ISOLATED_RULE],
      excludedTargetPaths: [],
      target: dir,
    },
  ];
  const accounted = [SEMGREP_ISOLATED_RULE, ...complement].sort();
  if (JSON.stringify(accounted) !== JSON.stringify(all)) {
    throw new Error(`Semgrep family ${family.configPath} rule subpartitions are not exhaustive and disjoint`);
  }
  if (new Set(partitions.map((partition) => partition.id)).size !== partitions.length) {
    throw new Error(`Semgrep family ${family.configPath} target subpartitions are duplicated`);
  }
  return partitions;
}

function subpartitionExclusions(partition: SemgrepRuleSubpartition): string[] {
  return [
    ...partition.excludedRuleIds.flatMap((id) => ["--exclude-rule", `src.scan.rules.semgrep.${id}`]),
    ...partition.excludedTargetPaths.flatMap((path) => ["--exclude", path]),
  ];
}

function assertSubpartitionOutput(
  family: SemgrepFamily,
  partition: SemgrepRuleSubpartition,
  output: SemgrepOutput,
): void {
  for (const result of output.results ?? []) {
    const matches = partition.includedRuleIds.filter((id) => ruleIdMatches(result.check_id, id));
    if (matches.length !== 1) {
      throw new Error(`Semgrep ${family.id}/${partition.id} emitted unaccounted rule ${result.check_id}`);
    }
  }
  const executed = [...new Set(output.time?.rules ?? [])].map((checkId) => {
    const matches = partition.includedRuleIds.filter((id) => ruleIdMatches(checkId, id));
    if (matches.length !== 1) throw new Error(`Semgrep ${family.id}/${partition.id} executed unaccounted rule ${checkId}`);
    return matches[0]!;
  }).sort();
  if (JSON.stringify(executed) !== JSON.stringify([...partition.includedRuleIds].sort())) {
    throw new Error(`Semgrep ${family.id}/${partition.id} did not execute its exact source-derived rule scope`);
  }
  const scanned = [...new Set((output.paths?.scanned ?? []).map((path) => resolve(path)))].sort();
  const excluded = new Set(partition.excludedTargetPaths.map((path) => resolve(partition.target, path)));
  if (scanned.some((path) => excluded.has(path))) {
    throw new Error(`Semgrep ${family.id}/${partition.id} scanned a target file that its exact argv excludes`);
  }
  if (partition.id.includes("/file-") && JSON.stringify(scanned) !== JSON.stringify([resolve(partition.target)])) {
    throw new Error(`Semgrep ${family.id}/${partition.id} did not scan exactly its one bounded target file`);
  }
}

function withoutFamily(output: SemgrepOutput, ruleIds: readonly string[]): SemgrepOutput {
  const belongs = (checkId: string): boolean => ruleIds.some((ruleId) => ruleIdMatches(checkId, ruleId));
  return {
    ...output,
    results: (output.results ?? []).filter((result) => !belongs(result.check_id)),
    time: { rules: (output.time?.rules ?? []).filter((ruleId) => !belongs(ruleId)) },
  };
}

function mergeVerifiedFamily(monolithic: SemgrepOutput, family: SemgrepFamily, verified: SemgrepOutput): SemgrepOutput {
  const retained = withoutFamily(monolithic, familyRuleIds(family.configPath));
  const record = (name: string, output: SemgrepOutput): SemgrepFamilyRecord => ({
    family: name,
    output,
    cache: "recomputed",
    key: "direct-execution",
    unitsExamined: Math.max(1, new Set(output.paths?.scanned ?? []).size),
  });
  return mergeSemgrepFamilyOutputs([
    record(`monolithic-without-${family.id}`, retained),
    record(family.id, verified),
  ]);
}

export function runSemgrep(dir: string, registryConfigs: readonly string[] = REGISTRY_PACKS): { result: SemgrepOutput; failure?: string } {
  const args = [
    ...registryConfigs.flatMap((p) => ["--config", p]),
    "--config", CUSTOM_RULES,
    "--exclude", "node_modules",
    "--disable-nosem",
    // #1710: no per-rule-per-file 5s wall-clock kill — a timed-out rule is a silent per-file recall
    // gap that varies with machine load (and at --timeout-threshold 3 starts skipping whole files).
    "--timeout", "0",
    "--json",
    // #1077: --verbose (not --quiet — the two are mutually exclusive) so paths.skipped is
    // populated; the extra diagnostic text it also prints goes to stderr, which this call never
    // reads, so stdout stays pure JSON.
    "--verbose",
    dir,
  ];
  const run = execSemgrep([...SEMGREP_PINNED_PREFIX, ...args]);
  if ("failure" in run) return { result: {}, failure: run.failure };
  const parsed = parseEnvelope(run.out);
  if (parsed.failure) return parsed;
  const injection = semgrepRuleFamilies(registryConfigs).find((family) => family.id === SEMGREP_PAIRED_FAMILY);
  if (!injection) return { result: {}, failure: `Semgrep family ${SEMGREP_PAIRED_FAMILY} is missing from the exhaustive plan` };
  const verified = runSemgrepFamily(dir, injection);
  if (verified.failure) return { result: {}, failure: verified.failure };
  return { result: mergeVerifiedFamily(parsed.result, injection, verified.result) };
}

function semgrepRuleFamilies(registryConfigs: readonly string[], localRulesRoot: string = CUSTOM_RULES): SemgrepFamily[] {
  if (registryConfigs.length !== REGISTRY_PACKS.length) {
    throw new Error(`Semgrep registry family count moved: expected ${REGISTRY_PACKS.length}, received ${registryConfigs.length}; every exact registry pack must be registered once`);
  }
  const registry = registryConfigs.map((configPath, index) => ({ id: `registry-${index}-${REGISTRY_PACKS[index]!.replaceAll("/", "-")}`, configPath }));
  const local = discoverLocalSemgrepFamilies(localRulesRoot);
  const families = [...registry, ...local];
  assertSemgrepFamilyPlan(families, [...registryConfigs, ...localSemgrepConfigYardstick(localRulesRoot)]);
  return families;
}

const SEMGREP_FAMILY_TAIL = [
  "--exclude", "node_modules",
  "--disable-nosem",
  "--timeout", "0",
  "--json",
  "--verbose",
  "--time",
] as const;

function receiptTarget(dir: string, target: string): string {
  const relativeTarget = relative(resolve(dir), resolve(target)).replaceAll("\\", "/");
  return relativeTarget === "" ? "<target-root>" : `<target-root>/${relativeTarget}`;
}

/** Semantic plan receipt built from the same constants, target bytes, and family registry execution consumes. */
export function semgrepExecutionPlanReceipt(
  registryConfigs: readonly string[],
  localRulesRoot: string = CUSTOM_RULES,
  targetRoot: string = process.cwd(),
): SemgrepExecutionPlanReceipt {
  const families = semgrepRuleFamilies(registryConfigs, localRulesRoot);
  return {
    schema: 4,
    strategy: "partitioned-families",
    families: families.map((family, ordinal) => {
      const policy = semgrepFamilyPolicy(family);
      const subpartitions = family.id === SEMGREP_PAIRED_FAMILY
        ? injectionRuleSubpartitions(family, targetRoot).map((partition) => ({
            id: partition.id,
            includedRuleIds: partition.includedRuleIds,
            excludedRuleIds: partition.excludedRuleIds,
            excludedTargetPaths: partition.excludedTargetPaths,
            target: receiptTarget(targetRoot, partition.target),
            argv: [
              ...policy.prefix,
              "--config", "<family-config>",
              ...subpartitionExclusions(partition),
              ...SEMGREP_FAMILY_TAIL,
              receiptTarget(targetRoot, partition.target),
            ],
          }))
        : undefined;
      return {
        ordinal,
        id: family.id,
        configSha256: createHash("sha256").update(readFileSync(family.configPath)).digest("hex"),
        argv: [...policy.prefix, "--config", "<family-config>", ...SEMGREP_FAMILY_TAIL, "<target-root>"],
        verification: policy.verification,
        ...(subpartitions ? { subpartitions } : {}),
      };
    }),
  };
}

function runSemgrepFamily(dir: string, family: SemgrepFamily): { result: SemgrepOutput; failure?: string } {
  const policy = semgrepFamilyPolicy(family);
  const once = (partition?: SemgrepRuleSubpartition): { result: SemgrepOutput; failure?: string } => {
    const args = [
      "--config", family.configPath,
      ...(partition ? subpartitionExclusions(partition) : []),
      ...SEMGREP_FAMILY_TAIL,
      partition?.target ?? dir,
    ];
    const run = execSemgrep([...policy.prefix, ...args]);
    if ("failure" in run) return { result: {}, failure: `${family.id}: ${run.failure}` };
    const parsed = parseEnvelope(run.out);
    if (parsed.failure) return { result: {}, failure: `${family.id}: ${parsed.failure}` };
    parsed.result.results ??= [];
    parsed.result.errors ??= [];
    parsed.result.paths ??= {};
    parsed.result.paths.scanned ??= [];
    parsed.result.paths.skipped ??= [];
    parsed.result.time ??= {};
    parsed.result.time.rules ??= [];
    if (partition) {
      try {
        assertSubpartitionOutput(family, partition, parsed.result);
      } catch (error) {
        return { result: {}, failure: error instanceof Error ? error.message : String(error) };
      }
    }
    return parsed;
  };
  if (policy.verification === "single") return once();
  let partitions: SemgrepRuleSubpartition[];
  try {
    partitions = injectionRuleSubpartitions(family, dir);
  } catch (error) {
    return { result: {}, failure: error instanceof Error ? error.message : String(error) };
  }
  const records: SemgrepFamilyRecord[] = [];
  for (const partition of partitions) {
    const execution = once(partition);
    if (execution.failure) return execution;
    records.push({
      family: `${family.id}/${partition.id}`,
      output: execution.result,
      cache: "recomputed",
      key: `direct-rule-partition:${partition.id}`,
      unitsExamined: Math.max(1, new Set(execution.result.paths?.scanned ?? []).size),
    });
  }
  const merged = mergeSemgrepFamilyOutputs(records);
  const complement = records.at(-1)?.output.paths?.scanned ?? [];
  const isolated = records.slice(0, -1).flatMap((record) => record.output.paths?.scanned ?? []);
  const stablePaths = (paths: readonly string[]): string => JSON.stringify([...new Set(paths.map((path) => resolve(path)))].sort());
  if (stablePaths(isolated) !== stablePaths(complement)) {
    return { result: {}, failure: `Semgrep ${family.id} target subpartitions do not exactly conserve the complement's scanned file scope` };
  }
  return { result: merged };
}

export async function runSemgrepPartitioned(
  dir: string,
  registryConfigs: readonly string[],
  cache: SemgrepFamilyCacheOptions,
): Promise<{ result: SemgrepOutput; records: SemgrepFamilyRecord[]; failure?: string }> {
  const families = semgrepRuleFamilies(registryConfigs);
  const portableCache = {
    ...cache,
    pathRoot: dir,
    implementation: JSON.stringify({
      mechanicalImplementation: cache.implementation,
      executionPlan: semgrepExecutionPlanReceipt(registryConfigs, CUSTOM_RULES, dir),
    }),
  };
  rejectUnregisteredSemgrepFamilyArtifacts(portableCache, new Set(families.map((family) => family.id)));
  const records: SemgrepFamilyRecord[] = [];
  for (const family of families) {
    let failure: string | undefined;
    const record = await executeSemgrepFamily(family, portableCache, () => {
      const run = runSemgrepFamily(dir, family);
      failure = run.failure;
      return run.result;
    }).catch((error) => {
      failure ??= error instanceof Error ? error.message : String(error);
      cache.onEvent?.(`SEMGREP FAMILY VERIFY FAIL ${family.id}: ${failure}`);
      return undefined;
    });
    if (!record) return { result: {}, records, failure: `partitioned Semgrep did not complete: ${failure}` };
    records.push(record);
  }
  assertSemgrepFamilyVerification(records, families, cache.mode);
  return { result: mergeSemgrepFamilyOutputs(records), records };
}

// A bare rule id (e.g. "harvey-route-noauth") matched against a JSON check_id, which carries a
// path-derived namespace prefix (e.g. "src.scan.rules.semgrep.harvey-route-noauth") — exact match,
// or the bare id as the final dotted segment.
function ruleIdMatches(checkId: string, bareId: string): boolean {
  return checkId === bareId || checkId.endsWith(`.${bareId}`);
}

// semgrep's own nosem semantics: a `nosem`/`nosemgrep` marker at the end of the matched line, or on
// the line immediately above it. `--disable-nosem` reports those matches but does NOT flag them in
// the OSS JSON (extra.is_ignored is absent — MEASURED 2026-07-25), so re-derive the marker here.
// #1093: a bare marker suppresses every rule matching that line, but semgrep's own
// `// nosemgrep: rule-id-a, rule-id-b` form scopes the suppression to ONLY the named rule(s) —
// Harvey's re-derivation used to ignore that scoping and withhold ANY finding on a marked line,
// moving an unrelated rule's match into the suppressed bucket instead of reporting it. Every
// withheld match is still counted in SEM-SUPPRESS-00, so nothing was silently hidden — this only
// fixes which bucket a withheld match lands in.
const NOSEM_MARKER = /\bnosem(?:grep)?\b(?:\s*:\s*(?<ids>.*))?/i;

// True when `idsText` (the text after `nosemgrep:`) names `checkId`, comma/whitespace-separated —
// an empty/unparseable list (a bare trailing colon) is treated as unscoped, matching semgrep's own
// "malformed scope suppresses everything" leniency.
function nosemScopeMatches(checkId: string, idsText: string): boolean {
  const ids = idsText
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  return ids.length === 0 || ids.some((id) => ruleIdMatches(checkId, id));
}

function markerSuppresses(line: string | undefined, checkId: string): boolean {
  if (!line) return false;
  const m = NOSEM_MARKER.exec(line);
  if (!m) return false;
  const ids = m.groups?.ids?.trim();
  return ids ? nosemScopeMatches(checkId, ids) : true;
}

export function partitionMarkerSuppressed(output: SemgrepOutput): { reported: SemgrepResult[]; suppressed: SemgrepResult[] } {
  const reported: SemgrepResult[] = [];
  const suppressed: SemgrepResult[] = [];
  const lines = new Map<string, string[]>();
  for (const r of output.results ?? []) {
    const line = r.start?.line;
    if (line === undefined) {
      reported.push(r);
      continue;
    }
    let src = lines.get(r.path);
    if (src === undefined) {
      try {
        src = readFileSync(r.path, "utf8").split("\n");
      } catch {
        src = [];
      }
      lines.set(r.path, src);
    }
    const marked = markerSuppresses(src[line - 1], r.check_id) || markerSuppresses(src[line - 2], r.check_id);
    (marked ? suppressed : reported).push(r);
  }
  return { reported, suppressed };
}

// #1093 (part 1): comment/string-aware code stripper. Replaces the CONTENTS of `//` line comments,
// `/* */` block comments (including multi-line — the LINE_PREFIX regex the two rules below used to
// carry, #1066, had no cross-line "am I inside a block comment" state, so a block comment whose
// interior lines didn't start with `*` still reached a guard-shaped token, MEASURED 2026-07-26) and
// string/template literals with spaces (newlines preserved), so a token search over the result can
// never mistake a guard-shaped word inside a comment or string for a real call.
export function stripCommentsAndStrings(text: string): string {
  let out = "";
  let i = 0;
  const n = text.length;
  while (i < n) {
    const two = text.slice(i, i + 2);
    if (two === "//") {
      while (i < n && text[i] !== "\n") {
        out += " ";
        i++;
      }
      continue;
    }
    if (two === "/*") {
      out += "  ";
      i += 2;
      while (i < n && text.slice(i, i + 2) !== "*/") {
        out += text[i] === "\n" ? "\n" : " ";
        i++;
      }
      if (i < n) {
        out += "  ";
        i += 2;
      }
      continue;
    }
    const c = text[i];
    if (c === '"' || c === "'" || c === "`") {
      out += " ";
      i++;
      while (i < n && text[i] !== c) {
        if (text[i] === "\\" && i + 1 < n) {
          out += text[i] === "\n" ? "\n" : " ";
          out += text[i + 1] === "\n" ? "\n" : " ";
          i += 2;
          continue;
        }
        out += text[i] === "\n" ? "\n" : " ";
        i++;
      }
      if (i < n) {
        out += " ";
        i++;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

// #1093 (part 1): the guard/role-check text searches auth.yml's harvey-route-noauth and
// harvey-authed-no-role-check used to run AS a semgrep `pattern-not-regex`, LINE_PREFIX-anchored so
// it couldn't see comments/strings on the matched line — but LINE_PREFIX has no memory of an
// unclosed block comment from a PRIOR line, so both rules went dark on a multi-line block comment
// wrapping a fake guard call (P-NOAUTH-BLOCK-COMMENT-GUARD). Both rules now match unconditionally
// in the YAML (see auth.yml) and this re-derives the same check itself, over the WHOLE matched
// function span (comment/string-stripped by the state machine above, not a per-line regex) — the
// same "re-derive it ourselves" shape partitionMarkerSuppressed already uses for nosem.
const ROUTE_NOAUTH_GUARD_RE =
  /\b((assert|require|ensure|authenticate|authorize|guard)[a-z0-9_]*|(?=[a-z0-9_]*(check|verify|with))[a-z0-9_]*(admin|permission|auth|session|tenant|role|access|user|login|signature|jwt|webhook|hmac|token)[a-z0-9_]*|constantTimeEqual|timingSafeEqual|getUser|getSession|getServerSession|getCurrentUser|getAuthUser|getAuthenticatedUser|auth)\s*\(/i;
const AUTHED_NO_ROLE_CHECK_GUARD_RE =
  /(is_?admin|hasrole|requirerole|checkrole|assertrole|assertadmin|requireadmin|ensureadmin|\bauthorize|\.role\b|permission|forbidden|\b403\b)/i;

const GUARD_TOKEN_RULES: { ruleId: string; tokenRe: RegExp }[] = [
  { ruleId: "harvey-route-noauth", tokenRe: ROUTE_NOAUTH_GUARD_RE },
  { ruleId: "harvey-authed-no-role-check", tokenRe: AUTHED_NO_ROLE_CHECK_GUARD_RE },
];

function isGuardedByToken(r: SemgrepResult, tokenRe: RegExp): boolean {
  const startLine = r.start?.line;
  const endLine = r.end?.line ?? startLine;
  if (startLine === undefined || endLine === undefined) return false;
  let span: string;
  try {
    span = readFileSync(r.path, "utf8").split("\n").slice(startLine - 1, endLine).join("\n");
  } catch {
    return false;
  }
  return tokenRe.test(stripCommentsAndStrings(span));
}

// #1300 / #126 option (1)+(2): guard helper names that belong to THIS target — discovered from its
// own source by discoverAuthGuards, plus any supplied per engagement via --auth-guards. Both regexes
// above are name lists, and a house style outside them (`mustBeOwner()`) produced a false positive
// on a genuinely guarded route (MEASURED 2026-07-30, pages/api/widgets/delete.js:4-8). Anchored on
// both sides so a supplied `auth` leaves `authorHistory(` alone.
// The negative lookbehind is load-bearing, not defensive: without it `\bhandler\s*\(` matches the
// DECLARATION `export default async function handler(req, res)`, so a route whose own entry point
// was mistaken for a guard cleared ITSELF. MEASURED 2026-07-31 — that plus the unfiltered discovery
// dropped 26 rows from the committed dry-run artifact, two of them planted positives.
function projectGuardRe(names: readonly string[]): RegExp | undefined {
  const safe = names.filter((n) => /^[A-Za-z_$][\w$]*$/.test(n));
  return safe.length === 0 ? undefined : new RegExp(`(?<!\\bfunction\\s)(?<!\\bclass\\s)\\b(?:${safe.join("|")})\\s*\\(`);
}

export function partitionGuardTokenSuppressed(
  output: SemgrepOutput,
  projectGuards: readonly string[] = [],
): { reported: SemgrepResult[]; guarded: SemgrepResult[] } {
  const reported: SemgrepResult[] = [];
  const guarded: SemgrepResult[] = [];
  const projectRe = projectGuardRe(projectGuards);
  for (const r of output.results ?? []) {
    const rule = GUARD_TOKEN_RULES.find((g) => ruleIdMatches(r.check_id, g.ruleId));
    const cleared =
      rule !== undefined &&
      (isGuardedByToken(r, rule.tokenRe) || (projectRe !== undefined && isGuardedByToken(r, projectRe)));
    (cleared ? guarded : reported).push(r);
  }
  return { reported, guarded };
}

// The disclosure half of --disable-nosem: the marker still removes the match from the finding list,
// but the deliverable now STATES that it happened and names every one (docs/design/
// mechanical-toolchain.md §2, which #1066 rewrote — it used to RECOMMEND nosemgrep as an FP
// control). An in-repo marker the report never mentions is a suppression the client is paying not
// to hear about.
export function semgrepSuppressionFinding(suppressed: SemgrepResult[], dir: string): Finding[] {
  if (suppressed.length === 0) return [];
  const at = suppressed.map((r) => `${relative(dir, r.path)}${r.start?.line ? `:${r.start.line}` : ""} (${r.check_id})`);
  return [
    {
      id: "SEM-SUPPRESS-00",
      title: `${suppressed.length} semgrep finding${suppressed.length === 1 ? "" : "s"} suppressed by in-repo nosemgrep markers`,
      severity: "Info",
      confidence: "N/A",
      category: "Coverage",
      taxonomy: "Coverage — findings suppressed by an in-repo marker",
      location: "(repo-wide)",
      status: "Open",
      evidence: `Semgrep matched at these locations, and each was withheld from the finding list by a \`nosem\`/\`nosemgrep\` marker committed in the codebase: ${at.join("; ")}.`,
      impact:
        "Each marker is a decision made inside the audited codebase, not by this audit, to keep a match out of the report. Some are legitimate false-positive suppressions; a marker can equally hide a real defect. Counted and named here so the number is never zero-by-silence.",
      fix: "Review each location against the named rule and confirm the suppression is still justified; remove any marker that is hiding a live defect.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    },
  ];
}

// Files semgrep did not analyse, derived from paths.scanned rather than from the flags we passed —
// so a semgrep default, a target-shipped ignore file, or the [INTERNAL] flag above disappearing all
// surface the same way instead of reading as "scanned and clean".
const SEMGREP_ANALYSABLE = /\.(js|jsx|mjs|cjs|ts|tsx)$/;
const SCOPE_SKIP_DIR = /^(node_modules|\.git)$/;

function analysableFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readEntriesSafe(dir).entries) {
    if (entry.isDirectory) {
      if (!SCOPE_SKIP_DIR.test(entry.name)) out.push(...analysableFiles(join(dir, entry.name)));
    } else if (SEMGREP_ANALYSABLE.test(entry.name)) {
      out.push(join(dir, entry.name));
    }
  }
  return out;
}

export function semgrepScopeFinding(dir: string, output: SemgrepOutput): Finding[] {
  const scanned = new Set(output.paths?.scanned ?? []);
  const unscanned = analysableFiles(dir).filter((f) => !scanned.has(f)).map((f) => relative(dir, f));
  if (unscanned.length === 0) return [];
  const shown = unscanned.slice(0, 25);
  return [
    {
      id: "SEM-SCOPE-00",
      title: `${unscanned.length} JS/TS source file${unscanned.length === 1 ? "" : "s"} semgrep did not scan`,
      severity: "Info",
      confidence: "N/A",
      category: "Coverage",
      taxonomy: "Coverage — source files semgrep did not scan",
      location: "(repo-wide)",
      status: "Open",
      evidence: `These files are in the scanned tree and carry a JS/TS extension the semgrep rules can analyse, but semgrep did not list them in paths.scanned: ${shown.join(", ")}${unscanned.length > shown.length ? `, and ${unscanned.length - shown.length} more` : ""}.`,
      impact:
        "No semgrep rule ran against this code, so the absence of footgun findings in these files means nothing was looked for — not that nothing is there. Recorded so the gap reads as 'not assessed' rather than clean.",
      fix: "Re-run the scan on a machine whose semgrep accepts --x-ignore-semgrepignore-files, or review these files by hand for the classes the semgrep rules cover.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    },
  ];
}

// #1077: `type` is a bare string for a whole-file syntax error but an array (e.g.
// ["PartialParsing", [...]]) for a partial-parse warning — normalize either shape to one line
// rather than let an array interpolate as "[object Object]" or similar.
function describeErrorType(type: string | unknown[] | undefined): string {
  if (Array.isArray(type)) return type.map((t) => (typeof t === "string" ? t : JSON.stringify(t))).join("/") || "unknown";
  return type ?? "unknown";
}

// #1077: the repo already states the principle this violates, verbatim, at runSemgrepOnFile below —
// "no match on a file the rules never evaluated must never be read as clean" — but only applied it
// on the fix pipeline's single-file re-run. The whole-tree engagement path discarded `errors[]`
// entirely: MEASURED 2026-07-25, a file with a syntax error still appears in `paths.scanned` (so
// semgrepScopeFinding's diff doesn't catch it either) while contributing zero findings —
// indistinguishable from a clean file. `paths.skipped` (files semgrep chose not to analyse for size/
// ignore/minified reasons, only populated at --verbose) is the same class of silence and reported
// alongside it, same contract as SEM-00/SEM-SCOPE-00: a counted, named row, never an absence.
export function semgrepErrorFinding(dir: string, output: SemgrepOutput): Finding[] {
  const errors = output.errors ?? [];
  const skipped = (output.paths?.skipped ?? []).filter((s) => s.path);
  if (errors.length === 0 && skipped.length === 0) return [];
  const errorLines = errors.map((e) => {
    const rel = e.path ? relative(dir, e.path) : "(unknown path)";
    const detail = e.message?.trim().split("\n")[0];
    return `${rel} (${describeErrorType(e.type)}${detail ? `: ${detail}` : ""})`;
  });
  const skippedLines = skipped.map((s) => `${relative(dir, s.path!)} (skipped: ${s.reason ?? "unspecified reason"})`);
  const all = [...errorLines, ...skippedLines];
  const shown = all.slice(0, 25);
  return [
    {
      id: "SEM-ERR-00",
      title: `${all.length} file${all.length === 1 ? "" : "s"} semgrep could not fully evaluate (parse error or skip)`,
      severity: "Info",
      confidence: "N/A",
      category: "Coverage",
      taxonomy: "Coverage — files semgrep errored on or skipped",
      location: "(repo-wide)",
      status: "Open",
      evidence: `Semgrep reported ${errors.length} per-file error(s) and ${skipped.length} skipped file(s) — these still count as "scanned" (an errored file even appears in paths.scanned) and would otherwise read as clean: ${shown.join("; ")}${all.length > shown.length ? `, and ${all.length - shown.length} more` : ""}.`,
      impact: "A file semgrep could not parse, or chose not to analyse (size limit, ignore rule, minified), contributes zero findings — the absence of footgun findings there means nothing was looked for, not that nothing is present.",
      fix: "Fix the syntax error (or reduce the file below semgrep's size/timeout limits) so semgrep can parse and analyse the file, then re-run the scan.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    },
  ];
}

// #1012 — the fix pipeline's detector re-run replays ONE finding's rule against ONE fixed file
// (src/fix/detector-rerun.ts). These are the harvey-* rule ids that CAN be replayed offline — read
// from the rule files themselves, so a renamed or deleted rule stops resolving (a rule that no
// longer exists would otherwise "not fire" and read as a fixed bug). A `p/*` REGISTRY-pack rule is a
// separate, ONLINE-only path (runRegistryPacksOnFile below, #1368) — corrected from this comment's
// own prior claim that a registry rule was "deliberately not resolvable": the network fetch it needs
// is the same one every real engagement scan already performs (runSemgrep), so declining it here was
// a determinism preference, not a capability limit, and had been recorded in impossibility's register.
export function harveyRuleIds(): Set<string> {
  const ids = new Set<string>();
  for (const file of readNamesSafe(CUSTOM_RULES)) {
    if (!file.endsWith(".yml")) continue;
    for (const m of readFileSync(join(CUSTOM_RULES, file), "utf8").matchAll(/^\s*-\s*id:\s*(harvey-[\w-]+)\s*$/gm)) {
      ids.add(m[1] as string);
    }
  }
  return ids;
}

// Run the custom rules against a single file. A per-path semgrep error (unparseable source, missing
// scanning root) is returned as `failure`, NOT as an empty result set: semgrep exits 0 having scanned
// nothing, and "no match on a file the rules never evaluated" must never be read as "clean".
//
// #1021: the scan is ROOTED at the target dir and narrowed to the one file with --include, rather
// than pointed straight at the file. A rule's own `paths:` filter is matched against the path
// RELATIVE TO THE SCANNING ROOT, so with the file itself as the root that path collapses to a bare
// basename and every path-filtered rule (auth.yml's harvey-authed-no-role-check, silent-failure.yml's
// harvey-void-async) silently matched nothing — a false clean, which computeGreen would have read as
// a fixed bug. `paths.scanned` is then checked so the narrowing itself can't reintroduce the same
// silence: a file the run never reached is a failure, not a clean detector.
export async function runSemgrepOnFile(absFile: string, root: string): Promise<{ result: SemgrepOutput; failure?: string }> {
  const rel = relative(root, absFile);
  // #1664: same completeness classification as runSemgrep — a non-zero exit or a signal means the
  // run did not complete (see execSemgrep's measurement), and its partial output must not feed the
  // pathError/paths.scanned checks below as if it were a finished scan.
  const run = await execSemgrepAsync(["--config", CUSTOM_RULES, "--include", rel, "--exclude", "node_modules", "--json", "--quiet", root]);
  if ("failure" in run) return { result: {}, failure: run.failure };
  const { result, failure } = parseEnvelope(run.out);
  if (failure) return { result: {}, failure };
  const pathError = (result.errors ?? []).find((e) => e.path === absFile);
  if (pathError) return { result, failure: `semgrep could not scan the file: ${pathError.message ?? pathError.type ?? "unknown error"}` };
  if (!(result.paths?.scanned ?? []).includes(absFile)) {
    return { result, failure: `semgrep did not scan ${rel} under ${root} (ignored by .gitignore/.semgrepignore, or an unrecognised extension)` };
  }
  return { result };
}

// #1368 — replay the registry packs (the same six every real scan fetches, REGISTRY_PACKS above)
// against ONE fixed file, for the fix-verification gate's registry-rule findings. Requires network
// (MEASURED 2026-07-30: `p/owasp-top-ten` alone resolves in ~1.4-2.2s; offline it times out with no
// output) — a caller with no network gets `failure` and must report notRun, never a false clean.
//
// `ruleIds` is `--time`'s exhaustive list of every rule id semgrep actually loaded and evaluated for
// this file, present whether or not it matched. That is the only way to tell "this taxonomy names a
// registry rule that ran and found nothing" from "this taxonomy is not a registry rule the packs
// carry at all" (renamed upstream, or not a semgrep taxonomy in the first place) — harvey-* rules
// have a local file `harveyRuleIds` can read for the same distinction; a registry pack has none.
export async function runRegistryPacksOnFile(absFile: string, root: string): Promise<{ result: SemgrepOutput; ruleIds: Set<string>; failure?: string }> {
  const rel = relative(root, absFile);
  const configArgs = REGISTRY_PACKS.flatMap((p) => ["--config", p]);
  // #1664: same completeness classification as runSemgrep — see execSemgrep's measurement.
  const run = await execSemgrepAsync([...configArgs, "--include", rel, "--exclude", "node_modules", "--json", "--quiet", "--time", root]);
  if ("failure" in run) return { result: {}, ruleIds: new Set(), failure: run.failure };
  const { result, failure } = parseEnvelope(run.out);
  if (failure) return { result: {}, ruleIds: new Set(), failure };
  const ruleIds = new Set(result.time?.rules ?? []);
  const pathError = (result.errors ?? []).find((e) => e.path === absFile);
  if (pathError) return { result, ruleIds, failure: `semgrep could not scan the file: ${pathError.message ?? pathError.type ?? "unknown error"}` };
  if (!(result.paths?.scanned ?? []).includes(absFile)) {
    return { result, ruleIds, failure: `semgrep did not scan ${rel} under ${root} (ignored by .gitignore/.semgrepignore, or an unrecognised extension)` };
  }
  return { result, ruleIds };
}

// Same disclosure contract as DEP-OSV-00/SEC-TH-GH-00/SEC-BUNDLE-00: a visible not-assessed row,
// never a silent skip — a missing semgrep binary must not read as "zero footguns found". #1664
// widened it from "binary missing" to any run that did not COMPLETE (a semgrep-core crash returning
// exit -10 used to reach the deliverable as a zero-finding clean scan); the reason names the
// observed exit code or signal, and the whole footgun pass is what was not scanned — partial output
// from a crashed run is discarded rather than delivered as if it covered the tree.
export function semgrepUnavailableFinding(reason: string): Finding {
  return {
    id: "SEM-00",
    title: "Semgrep footgun scan did not run to completion",
    severity: "Info",
    confidence: "N/A",
    category: "Next.js/web footgun",
    taxonomy: "Next.js/web footgun — coverage not assessed",
    location: "(repo-wide)",
    status: "Open",
    evidence: `Semgrep failed to run: ${reason}. No file in this tree was semgrep-scanned on this pass.`,
    impact: "Semgrep footgun coverage for this engagement is incomplete for this pass — a disclosed coverage gap, not a finding of zero footguns.",
    fix: "Install semgrep on the scanning machine (see this file's header) — or, if the evidence names an exit code or signal, investigate the crash — and re-run the scan.",
    value: 1,
    ease: 3,
    safety: 5,
  };
}

// #1664: the row that means the mechanical scan's semgrep pass itself did not complete. A gate that
// SCORES findings (validate-calibration) must stop on this rather than render a recall table over a
// scan that never ran — "113 rules have never been shown to work" and "the scanner crashed" lead a
// reader to opposite actions. On the engagement path the row is the correct deliverable; on a
// measurement path it invalidates the measurement.
export function scanDidNotRun(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.id === "SEM-00");
}
