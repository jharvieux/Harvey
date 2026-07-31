// Runs the vendored Splinter lint set (src/scan/rules/splinter.sql) against a connected local
// Postgres and normalizes the result into the same AdvisorLint shape hosted-mode `get_advisors`
// responses use, so src/scan/supabase-advisors.ts#parseAdvisorFindings can turn either source
// into Findings with one shared severity/precision mapping.
//
// Invocation: `psql <connectionString> -t -A -F <sep> -f splinter.sql`. `-t` (tuples only) drops
// column headers/row-count footers; `-A -F <sep>` gives one delimited row per lint, matching
// the query's 10-column output (name, title, level, facing, categories, description, detail,
// remediation, metadata, cache_key). psql still echoes non-SELECT command tags (SET, DO) and can
// surface a WARNING for the leading `set local search_path` (harmless outside a transaction
// block — see the recorded fixture, src/scan/fixtures/splinter-out.txt); parseSplinterPipeText
// discards any line that doesn't split into exactly that 10-column shape, so none of that noise
// needs to be special-cased.
//
// #1264 — the separator used to be `|`, which four of the ten columns can legitimately contain:
// `detail`, `metadata` and `cache_key` are `format()`ed from live identifiers, and a Postgres
// identifier may carry any character when quoted. MEASURED 2026-07-30 against postgres:16-alpine
// with `create table public."child|B" (…, constraint "fk|pipe" foreign key …)`: the real
// splinter.sql `unindexed_foreign_keys` row split into SIXTEEN pipe fields, so the `!== 10` guard
// dropped a genuine lint with no finding, no count and no disclosure row. The same query under
// `-F <US>` (ASCII 0x1F unit separator) splits into exactly 10, identifiers intact. Text output
// from Postgres does not carry control bytes unless a value literally contains one, so the unit
// separator removes the collision rather than narrowing it. The pipe path is still parsed —
// src/scan/fixtures/splinter-out.txt is a recorded artifact of a real pre-#1264 run — and any
// line that looks like a lint row but does not yield 10 fields is now COUNTED, so a residual
// drop reaches SB-SPLINTER-00 instead of vanishing.
//
// Requires the `psql` binary (ships with the Supabase CLI / any Postgres client install) —
// same class of external-tool dependency as semgrep/gitleaks/osv-scanner elsewhere in this
// toolchain (src/scan/semgrep.ts, src/scan/secrets.ts, src/scan/mechanical.ts).

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { assertNoSecretInArgv, splitPgPassword } from "../secret-argv.js";
import type { AdvisorLint, AdvisorsResponse } from "./supabase-advisors.js";

const SPLINTER_SQL_PATH = fileURLToPath(new URL("./rules/splinter.sql", import.meta.url));
const LEVELS = new Set(["ERROR", "WARN", "INFO"]);
const FIELD_SEP = "\u001f";
const SPLINTER_COLUMNS = 10;

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

// Splits `psql -t -A -F <sep> -f splinter.sql` output into one raw row per lint, discarding
// command-tag/warning noise (SET, DO, "psql:...: WARNING", blank lines) — none of that ever
// splits into the query's fixed 10-column shape.
//
// `unparsedRows` counts lines that ARE lint rows (their third field is a Splinter level) but did
// not yield 10 columns because a value contained the separator. Under FIELD_SEP that count is
// expected to stay 0; it is carried rather than assumed so a residual drop is disclosed
// (SB-SPLINTER-00) instead of silently shrinking the advisor set — #1264.
export function parseSplinterPipeText(raw: string): { rows: SplinterRow[]; unparsedRows: number } {
  const sep = raw.includes(FIELD_SEP) ? FIELD_SEP : "|";
  const rows: SplinterRow[] = [];
  let unparsedRows = 0;
  for (const line of raw.split("\n")) {
    const fields = line.split(sep);
    if (fields.length !== SPLINTER_COLUMNS) {
      if (fields.length > SPLINTER_COLUMNS && LEVELS.has(fields[2]!)) unparsedRows++;
      continue;
    }
    const [name, title, level, facing, categories, description, detail, remediation, metadata, cache_key] = fields;
    if (!name || !title || !level || !LEVELS.has(level)) continue;
    rows.push({ name, title, level, facing, categories, description, detail, remediation, metadata, cache_key });
  }
  return { rows, unparsedRows };
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
  const { rows, unparsedRows } = parseSplinterPipeText(raw);
  return { lints: splinterRowsToAdvisorLints(rows), unparsedRows };
}

// Not unit-tested — same as runSemgrep (src/scan/semgrep.ts): it shells out to a real external
// binary against a real DB connection, so it's exercised by a live confirmation run instead
// (docs/runbooks/dry-run-calibration.md §9). parseSplinterOutput above is the tested layer.
export function runSplinter(connectionString: string): AdvisorsResponse {
  let out: string;
  // #1297 — the connection string is the CLIENT's, so its password is a real credential of the
  // database being audited. libpq reads it from PGPASSWORD, keeping it out of the world-readable argv.
  const { conninfo, password } = splitPgPassword(connectionString);
  const argv = [conninfo, "-t", "-A", "-F", FIELD_SEP, "-f", SPLINTER_SQL_PATH];
  assertNoSecretInArgv("runSplinter", argv, [password]);
  try {
    out = execFileSync("psql", argv, {
      encoding: "utf8",
      env: password ? { ...process.env, PGPASSWORD: password } : process.env,
      maxBuffer: 1024 * 1024 * 64,
    });
  } catch (err) {
    const e = err as { stdout?: string };
    if (typeof e.stdout === "string" && e.stdout.length > 0) out = e.stdout;
    else throw err;
  }
  return parseSplinterOutput(out);
}
