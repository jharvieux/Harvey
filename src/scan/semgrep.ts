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

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { readEntriesSafe, readNamesSafe } from "../fs-walk.js";
import type { Finding, Severity } from "../findings.js";
import { mechanicalFinding } from "./common.js";

// The whole custom-rule directory is loaded as one --config; each security batch adds its own
// `<batch>.yml` here (no shared file → conflict-free parallel batches).
const CUSTOM_RULES = new URL("./rules/semgrep/", import.meta.url).pathname;

// The maintained registry packs every real engagement scan fetches (runSemgrep below) — shared with
// runRegistryPacksOnFile's single-file replay (#1368) so the two can never drift apart.
const REGISTRY_PACKS = ["p/typescript", "p/react", "p/nextjs", "p/owasp-top-ten", "p/secrets", "p/security-audit"];

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
  return (output.results ?? []).map((r, i) => {
    const meta = r.extra?.metadata;
    const severity = (meta?.harveySeverity as Severity | undefined) ?? severityFromSemgrep(r.extra?.severity);
    const high = r.extra?.severity === "ERROR" && meta?.confidence === "HIGH" && !isAuditRule(r.check_id);
    const message = r.extra?.message?.trim().split("\n")[0] ?? "Semgrep match";
    // #996: a workflow-file finding is a fact about the CI pipeline, not the app — its own
    // fully-reported non-grading category, with the routing reason stated on the finding.
    const ciWorkflow = CI_WORKFLOW_PATH.test(r.path);
    const impact = r.extra?.message ?? "See the rule's message for the specific risk.";
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
export function runSemgrep(dir: string): { result: SemgrepOutput; failure?: string } {
  const args = [
    ...REGISTRY_PACKS.flatMap((p) => ["--config", p]),
    "--config", CUSTOM_RULES,
    "--exclude", "node_modules",
    "--disable-nosem",
    "--json",
    // #1077: --verbose (not --quiet — the two are mutually exclusive) so paths.skipped is
    // populated; the extra diagnostic text it also prints goes to stderr, which this call never
    // reads, so stdout stays pure JSON.
    "--verbose",
    dir,
  ];
  const attempt = (argv: string[]): { out: string } | { failure: string; enoent: boolean } => {
    try {
      return { out: execFileSync("semgrep", argv, { encoding: "utf8", maxBuffer: 1024 * 1024 * 128 }) };
    } catch (err) {
      const e = err as { stdout?: string; code?: string; message?: string };
      if (typeof e.stdout === "string" && e.stdout.length > 0) return { out: e.stdout };
      const enoent = e.code === "ENOENT";
      return { failure: enoent ? "semgrep not found on PATH" : (e.message ?? "semgrep failed with no output"), enoent };
    }
  };
  let run = attempt(["--x-ignore-semgrepignore-files", ...args]);
  if ("failure" in run && !run.enoent) run = attempt(args);
  if ("failure" in run) return { result: {}, failure: run.failure };
  return { result: JSON.parse(run.out) as SemgrepOutput };
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

export function partitionGuardTokenSuppressed(output: SemgrepOutput): { reported: SemgrepResult[]; guarded: SemgrepResult[] } {
  const reported: SemgrepResult[] = [];
  const guarded: SemgrepResult[] = [];
  for (const r of output.results ?? []) {
    const rule = GUARD_TOKEN_RULES.find((g) => ruleIdMatches(r.check_id, g.ruleId));
    (rule && isGuardedByToken(r, rule.tokenRe) ? guarded : reported).push(r);
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
export function runSemgrepOnFile(absFile: string, root: string): { result: SemgrepOutput; failure?: string } {
  const rel = relative(root, absFile);
  let out: string;
  try {
    out = execFileSync("semgrep", ["--config", CUSTOM_RULES, "--include", rel, "--exclude", "node_modules", "--json", "--quiet", root], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024 * 128,
    });
  } catch (err) {
    const e = err as { stdout?: string; code?: string; message?: string };
    if (typeof e.stdout === "string" && e.stdout.length > 0) out = e.stdout;
    else return { result: {}, failure: e.code === "ENOENT" ? "semgrep not found on PATH" : (e.message ?? "semgrep failed with no output") };
  }
  const result = JSON.parse(out) as SemgrepOutput;
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
export function runRegistryPacksOnFile(absFile: string, root: string): { result: SemgrepOutput; ruleIds: Set<string>; failure?: string } {
  const rel = relative(root, absFile);
  const configArgs = REGISTRY_PACKS.flatMap((p) => ["--config", p]);
  let out: string;
  try {
    out = execFileSync(
      "semgrep",
      [...configArgs, "--include", rel, "--exclude", "node_modules", "--json", "--quiet", "--time", root],
      { encoding: "utf8", maxBuffer: 1024 * 1024 * 128 },
    );
  } catch (err) {
    const e = err as { stdout?: string; code?: string; message?: string };
    if (typeof e.stdout === "string" && e.stdout.length > 0) out = e.stdout;
    else return { result: {}, ruleIds: new Set(), failure: e.code === "ENOENT" ? "semgrep not found on PATH" : (e.message ?? "semgrep failed with no output") };
  }
  const result = JSON.parse(out) as SemgrepOutput;
  const ruleIds = new Set(result.time?.rules ?? []);
  const pathError = (result.errors ?? []).find((e) => e.path === absFile);
  if (pathError) return { result, ruleIds, failure: `semgrep could not scan the file: ${pathError.message ?? pathError.type ?? "unknown error"}` };
  if (!(result.paths?.scanned ?? []).includes(absFile)) {
    return { result, ruleIds, failure: `semgrep did not scan ${rel} under ${root} (ignored by .gitignore/.semgrepignore, or an unrecognised extension)` };
  }
  return { result, ruleIds };
}

// Same disclosure contract as DEP-OSV-00/SEC-TH-GH-00/SEC-BUNDLE-00: a visible not-assessed row,
// never a silent skip — a missing semgrep binary must not read as "zero footguns found".
export function semgrepUnavailableFinding(reason: string): Finding {
  return {
    id: "SEM-00",
    title: "Semgrep footgun scan did not run",
    severity: "Info",
    confidence: "N/A",
    category: "Next.js/web footgun",
    taxonomy: "Next.js/web footgun — coverage not assessed",
    location: "(repo-wide)",
    status: "Open",
    evidence: `Semgrep failed to run: ${reason}`,
    impact: "Semgrep footgun coverage for this engagement is incomplete for this pass — a disclosed coverage gap, not a finding of zero footguns.",
    fix: "Install semgrep on the scanning machine (see this file's header) and re-run the scan.",
    value: 1,
    ease: 3,
    safety: 5,
  };
}
