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
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import type { Finding, Severity } from "../findings.js";
import { mechanicalFinding } from "./common.js";

// The whole custom-rule directory is loaded as one --config; each security batch adds its own
// `<batch>.yml` here (no shared file → conflict-free parallel batches).
const CUSTOM_RULES = new URL("./rules/semgrep/", import.meta.url).pathname;

export interface SemgrepResult {
  check_id: string;
  path: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string; // ERROR | WARNING | INFO
    // cwe/owasp (#455): carried by both the registry p/owasp-top-ten pack and, where added, our
    // harvey-* custom rules — see each rule's `metadata:` block in ./rules/semgrep/*.yml.
    metadata?: { confidence?: string; harveySeverity?: string; cwe?: string[]; owasp?: string[] };
  };
}

export interface SemgrepOutput {
  results?: SemgrepResult[];
}

const SEVERITY_FROM_SEMGREP: Record<string, Severity> = { ERROR: "High", WARNING: "Medium", INFO: "Low" };

function isAuditRule(checkId: string): boolean {
  return checkId.includes(".audit.") || checkId.endsWith(".audit");
}

export function parseSemgrepFindings(output: SemgrepOutput): Finding[] {
  return (output.results ?? []).map((r, i) => {
    const meta = r.extra?.metadata;
    const severity = (meta?.harveySeverity as Severity | undefined) ?? SEVERITY_FROM_SEMGREP[r.extra?.severity ?? "WARNING"] ?? "Medium";
    const high = r.extra?.severity === "ERROR" && meta?.confidence === "HIGH" && !isAuditRule(r.check_id);
    const message = r.extra?.message?.trim().split("\n")[0] ?? "Semgrep match";
    return mechanicalFinding({
      id: `SEM-${i + 1}`,
      title: `${r.check_id}: ${message}`,
      severity,
      category: "Next.js/web footgun",
      taxonomy: r.check_id,
      location: `${r.path}${r.start?.line ? `:${r.start.line}` : ""}`,
      evidence: r.extra?.message ?? `Semgrep rule ${r.check_id} matched.`,
      impact: r.extra?.message ?? "See the rule's message for the specific risk.",
      fix: "Review the matched code path against the rule's remediation guidance.",
      precisionTier: high ? "high" : "review",
      // #455 — populate only from the rule's own declared metadata, never invented here.
      cwe: meta?.cwe?.length ? meta.cwe : undefined,
      owasp: meta?.owasp?.length ? meta.owasp : undefined,
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
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(full));
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

export function runSemgrep(dir: string): SemgrepOutput {
  const args = [
    "--config", "p/typescript",
    "--config", "p/react",
    "--config", "p/nextjs",
    "--config", "p/owasp-top-ten",
    "--config", "p/secrets",
    "--config", "p/security-audit",
    "--config", CUSTOM_RULES,
    "--exclude", "node_modules",
    "--json",
    "--quiet",
    dir,
  ];
  let out: string;
  try {
    out = execFileSync("semgrep", args, { encoding: "utf8", maxBuffer: 1024 * 1024 * 128 });
  } catch (err) {
    const e = err as { stdout?: string };
    if (typeof e.stdout === "string" && e.stdout.length > 0) out = e.stdout;
    else throw err;
  }
  return JSON.parse(out) as SemgrepOutput;
}
