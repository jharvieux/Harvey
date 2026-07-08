// Next.js/web footguns via Semgrep OSS: dangerouslySetInnerHTML, permissive CORS,
// service-role-in-client, open redirects (custom rules — src/scan/rules/semgrep-nextjs-
// supabase.yml) layered on the registry security packs.
//
// Semgrep is an external CLI binary, not an npm dependency. Install: `pip install semgrep`
// or `brew install semgrep` (https://semgrep.dev/docs/getting-started/). `--config p/*`
// packs are fetched from the Semgrep registry over the network on first run (cached after).
//
// Invocation:
//   semgrep --config p/typescript --config p/react --config p/nextjs --config p/owasp-top-ten \
//     --config src/scan/rules/semgrep-nextjs-supabase.yml --json <dir>
//
// Trust boundary: severity ERROR + metadata.confidence HIGH + not a `.audit.`-suffixed rule
// is "high" precision (docs/design/mechanical-toolchain.md); everything else is "review".
//
// Missing security-headers/CSP is checked separately below (checkMissingSecurityHeaders) —
// it's a next.config shape check, not something a Semgrep AST pattern expresses reliably.

import { execFileSync } from "node:child_process";
import type { Finding, Severity } from "../findings.js";
import { mechanicalFinding } from "./common.js";

const CUSTOM_RULES = new URL("./rules/semgrep-nextjs-supabase.yml", import.meta.url).pathname;

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

// next.config.{js,ts,mjs} headers() shape check — flags a headers() function whose returned
// values don't mention Content-Security-Policy. Heuristic: a project may set CSP via a
// middleware or a hosting-platform config instead, so this is always "review" tier.
export function checkMissingSecurityHeaders(configPath: string, configSource: string): Finding[] {
  const definesHeaders = /\bheaders\s*(:|\()\s*(async)?\s*\(?\)?\s*(=>|\{)/.test(configSource);
  if (!definesHeaders) return [];
  if (/content-security-policy/i.test(configSource)) return [];
  return [
    mechanicalFinding({
      id: "SEM-CSP-1",
      title: "next.config headers() defined with no Content-Security-Policy",
      severity: "Medium",
      category: "Next.js/web footgun",
      taxonomy: "Missing security headers",
      location: configPath,
      evidence: `${configPath} defines a headers() function but no header sets Content-Security-Policy.`,
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
    "--config", CUSTOM_RULES,
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
