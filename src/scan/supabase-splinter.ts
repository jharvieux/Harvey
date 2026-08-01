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
// src/scan/fixtures/splinter-out.txt is a recorded artifact of a real pre-#1264 run — and a line
// still identifiable as a lint row (its third field is a Splinter level) that does not yield 10
// fields is now COUNTED, so that residual drop reaches SB-SPLINTER-00 instead of vanishing.
// It is not every drop: see `parseSplinterPipeText` for the shape that evades the count, and
// SB-SPLINTER-00's own `evidence`, which states that bound to the reader of the report.
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
//
// The level test is what tells a lint row apart from psql's command-tag/warning noise, so it also
// bounds the count: a separator inside `name` or `title` shifts the level out of fields[2] and the
// row is dropped uncounted. That residual is disclosed in SB-SPLINTER-00's `evidence` rather than
// left to this comment — a bound nobody outside this file can read is not a disclosure (#1317).
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

// #1755 — the #1664/#1752 classification (execSemgrep/runOsvScanner) applied to psql. MEASURED
// 2026-07-31 against psql 18.4 client / Postgres 16.14 server, docker-local: WITHOUT
// `-v ON_ERROR_STOP=1` (the invocation this file shipped until now), a runtime error anywhere in
// splinter.sql's single compound lint query — one `1857`-line statement, so any lint's failure
// aborts the WHOLE statement — makes psql print only the SET/DO command-tag noise (0 lint rows,
// not a partial list: Postgres does not stream rows from an aborted statement) and STILL EXIT 0.
// A fully failed lint pass therefore read as "zero advisories, clean scan" with no exception ever
// reaching this function's `catch`, on the paid tier where the client granted DB access
// specifically for completeness. `-v ON_ERROR_STOP=1` (MEASURED same setup) turns that into exit
// 3, so a script error now reaches this function as a thrown, classifiable failure instead of a
// false-clean success. A separate multi-statement probe (two independent top-level SELECTs, the
// first succeeding before the second fails) DID show a genuine partial row on stdout before the
// non-zero exit — splinter.sql itself has no such second independent SELECT, but the classification
// below refuses ANY non-zero exit's stdout regardless, so that shape is covered too if the vendored
// file ever changes shape. `psql`'s own documented meaning: 0 = success, 1 = fatal error of its
// own (bad option, failed to connect), 2 = connection to the server went bad mid-session, 3 = a script
// error under ON_ERROR_STOP. None of 1/2/3, nor a signal, is treated as complete.
export function runSplinter(connectionString: string): AdvisorsResponse {
  // #1297 — the connection string is the CLIENT's, so its password is a real credential of the
  // database being audited. libpq reads it from PGPASSWORD, keeping it out of the world-readable argv.
  const { conninfo, password } = splitPgPassword(connectionString);
  const argv = [conninfo, "-v", "ON_ERROR_STOP=1", "-t", "-A", "-F", FIELD_SEP, "-f", SPLINTER_SQL_PATH];
  assertNoSecretInArgv("runSplinter", argv, [password]);
  try {
    const out = execFileSync("psql", argv, {
      encoding: "utf8",
      env: password ? { ...process.env, PGPASSWORD: password } : process.env,
      maxBuffer: 1024 * 1024 * 64,
    });
    return parseSplinterOutput(out);
  } catch (err) {
    const e = err as { code?: string; status?: number | null; signal?: string | null };
    if (e.code === "ENOENT") return { lints: [], failure: "psql not found on PATH" };
    const how = e.signal ? `killed by signal ${e.signal}` : `exited with code ${e.status ?? "unknown"}`;
    // Never parse the caught stdout as the advisor set — under ON_ERROR_STOP a non-zero exit means
    // the lint query did not run to completion, and #1755's own measurement shows a fully-failed
    // run's stdout reads as a legitimate-looking empty result, not an obviously-truncated one.
    return { lints: [], failure: `psql run did not complete (${how})` };
  }
}
