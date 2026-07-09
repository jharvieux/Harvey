// Runs the vendored Splinter lint set (src/scan/rules/splinter.sql) against a connected local
// Postgres and normalizes the result into the same AdvisorLint shape hosted-mode `get_advisors`
// responses use, so src/scan/supabase-advisors.ts#parseAdvisorFindings can turn either source
// into Findings with one shared severity/precision mapping.
//
// Invocation: `psql <connectionString> -t -A -F'|' -f splinter.sql`. `-t` (tuples only) drops
// column headers/row-count footers; `-A -F'|'` gives one pipe-delimited row per lint, matching
// the query's 10-column output (name|title|level|facing|categories|description|detail|
// remediation|metadata|cache_key). psql still echoes non-SELECT command tags (SET, DO) and can
// surface a WARNING for the leading `set local search_path` (harmless outside a transaction
// block — see the recorded fixture, src/scan/fixtures/splinter-out.txt); parseSplinterPipeText
// discards any line that doesn't split into exactly that 10-column shape, so none of that noise
// needs to be special-cased.
//
// Requires the `psql` binary (ships with the Supabase CLI / any Postgres client install) —
// same class of external-tool dependency as semgrep/gitleaks/osv-scanner elsewhere in this
// toolchain (src/scan/semgrep.ts, src/scan/secrets.ts, src/scan/mechanical.ts).

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import type { AdvisorLint, AdvisorsResponse } from "./supabase-advisors.js";

const SPLINTER_SQL_PATH = fileURLToPath(new URL("./rules/splinter.sql", import.meta.url));
const LEVELS = new Set(["ERROR", "WARN", "INFO"]);

// A splinter.sql result row in its rawest (text-protocol) form: `categories` as a Postgres
// array literal ("{SECURITY}") and `metadata` as a JSON string, exactly as psql's pipe output
// carries them.
interface SplinterRow {
  name: string;
  title: string;
  level: string;
  facing?: string;
  categories?: string;
  description?: string;
  detail?: string;
  remediation?: string;
  metadata?: string;
  cache_key?: string;
}

// Splits `psql -t -A -F'|' -f splinter.sql` output into one raw row per lint, discarding
// command-tag/warning noise (SET, DO, "psql:...: WARNING", blank lines) — none of that ever
// splits into the query's fixed 10-column shape.
export function parseSplinterPipeText(raw: string): SplinterRow[] {
  const rows: SplinterRow[] = [];
  for (const line of raw.split("\n")) {
    const fields = line.split("|");
    if (fields.length !== 10) continue;
    const [name, title, level, facing, categories, description, detail, remediation, metadata, cache_key] = fields;
    if (!name || !title || !level || !LEVELS.has(level)) continue;
    rows.push({ name, title, level, facing, categories, description, detail, remediation, metadata, cache_key });
  }
  return rows;
}

function parsePgTextArray(v: string): string[] {
  const trimmed = v.trim().replace(/^\{/, "").replace(/\}$/, "");
  return trimmed.length === 0 ? [] : trimmed.split(",").map((s) => s.trim()).filter(Boolean);
}

// Normalizes psql's text-protocol row shape (categories as a Postgres array literal, metadata
// as a JSON string) into the strict AdvisorLint shape — a malformed/empty metadata field is
// dropped rather than thrown, since one bad row shouldn't sink the whole lint set.
export function splinterRowsToAdvisorLints(rows: SplinterRow[]): AdvisorLint[] {
  return rows
    .filter((r) => LEVELS.has(r.level))
    .map((r) => {
      let metadata: AdvisorLint["metadata"];
      try {
        metadata = r.metadata ? (JSON.parse(r.metadata) as AdvisorLint["metadata"]) : undefined;
      } catch {
        metadata = undefined;
      }
      return {
        name: r.name,
        title: r.title,
        level: r.level as AdvisorLint["level"],
        facing: r.facing,
        categories: r.categories ? parsePgTextArray(r.categories) : undefined,
        description: r.description,
        detail: r.detail,
        remediation: r.remediation,
        metadata,
        cache_key: r.cache_key,
      };
    });
}

export function parseSplinterOutput(raw: string): AdvisorsResponse {
  return { lints: splinterRowsToAdvisorLints(parseSplinterPipeText(raw)) };
}

// Not unit-tested — same as runSemgrep (src/scan/semgrep.ts): it shells out to a real external
// binary against a real DB connection, so it's exercised by a live confirmation run instead
// (docs/runbooks/dry-run-calibration.md §9). parseSplinterOutput above is the tested layer.
export function runSplinter(connectionString: string): AdvisorsResponse {
  let out: string;
  try {
    out = execFileSync("psql", [connectionString, "-t", "-A", "-F", "|", "-f", SPLINTER_SQL_PATH], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024 * 64,
    });
  } catch (err) {
    const e = err as { stdout?: string };
    if (typeof e.stdout === "string" && e.stdout.length > 0) out = e.stdout;
    else throw err;
  }
  return parseSplinterOutput(out);
}
