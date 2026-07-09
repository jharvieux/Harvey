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
import { join } from "node:path";
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
    metadata?: { confidence?: string; harveySeverity?: string };
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
