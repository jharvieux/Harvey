import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SecretInArgvError } from "../secret-argv.js";
import { parseAdvisorFindings } from "./supabase-advisors.js";
import { parseSplinterOutput, parseSplinterPipeText, runSplinter, splinterRowsToAdvisorLints } from "./supabase-splinter.js";

vi.mock("node:child_process", () => ({ execFileSync: vi.fn(() => "") }));

// #54 — recorded `psql <local-db> -t -A -F'|' -f splinter.sql` output from a real connected-tier
// confirmation run (docs/runbooks/dry-run-calibration.md §9, 2026-07-09), against the B8/M7
// calibration fixtures. Includes the leading WARNING/SET/DO noise psql actually emits, so this
// also proves the parser's noise-filtering, not just its happy-path row parsing.
const FIXTURE_PATH = fileURLToPath(new URL("./fixtures/splinter-out.txt", import.meta.url));
const FIXTURE_RAW = readFileSync(FIXTURE_PATH, "utf8");

describe("parseSplinterPipeText", () => {
  it("discards psql's WARNING/SET/DO command-tag noise and parses only the 10-column data rows", () => {
    const { rows } = parseSplinterPipeText(FIXTURE_RAW);
    expect(rows).toHaveLength(33);
    expect(rows.every((r) => r.name && r.title && r.level)).toBe(true);
  });

  it("returns nothing for text with no valid 10-column rows", () => {
    expect(parseSplinterPipeText("psql:foo.sql:1: WARNING: bla\nSET\nDO\n\n")).toEqual({ rows: [], unparsedRows: 0 });
  });
});

// #1264. The ten field values below are VERBATIM psql output, not hand-written: captured
// 2026-07-30 from `psql -t -A -F <sep> -f src/scan/rules/splinter.sql` against postgres:16-alpine
// seeded with `create table public."parent|A" (id int primary key)` and
// `create table public."child|B" (…, constraint "fk|pipe" foreign key (pid) references public."parent|A"(id))`
// plus the anon/authenticated/service_role roles splinter.sql requires. Three of the ten columns
// (detail, metadata, cache_key) carry the identifiers' pipes, because splinter.sql `format()`s
// them in — so the same run under `-F '|'` produced SIXTEEN fields and the old `!== 10` guard
// dropped a real lint in silence.
const PIPE_BEARING_FIELDS = [
  "unindexed_foreign_keys",
  "Unindexed foreign keys",
  "INFO",
  "EXTERNAL",
  "{PERFORMANCE}",
  "Identifies foreign key constraints without a covering index, which can impact database performance.",
  "Table \\`public.child|B\\` has a foreign key \\`fk|pipe\\` without a covering index. This can lead to suboptimal query performance.",
  "https://supabase.com/docs/guides/database/database-linter?lint=0001_unindexed_foreign_keys",
  '{"name": "child|B", "type": "table", "schema": "public", "fkey_name": "fk|pipe", "fkey_columns": [2]}',
  "unindexed_foreign_keys_public_child|B_fk|pipe",
];
const PSQL_NOISE = "psql:splinter.sql:18: WARNING:  SET LOCAL can only be used in transaction blocks\nSET\nDO\n";
const UNIT_SEPARATED = PSQL_NOISE + PIPE_BEARING_FIELDS.join("\u001f") + "\n";
const PIPE_SEPARATED = PSQL_NOISE + PIPE_BEARING_FIELDS.join("|") + "\n";

describe("a lint whose identifiers contain the pipe character (#1264)", () => {
  it("survives the parser under the unit separator, with every identifier intact", () => {
    const { rows, unparsedRows } = parseSplinterPipeText(UNIT_SEPARATED);
    expect(unparsedRows).toBe(0);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.detail).toContain("public.child|B");
    expect(rows[0]?.cache_key).toBe("unindexed_foreign_keys_public_child|B_fk|pipe");
  });

  it("reaches a Finding whose id and metadata still carry the piped identifiers", () => {
    const [finding] = parseAdvisorFindings(parseSplinterOutput(UNIT_SEPARATED));
    expect(finding?.id).toBe("SB-ADV-unindexed_foreign_keys_public_child|B_fk|pipe");
    expect(finding?.location).toBe("public.child|B");
  });

  // The negative direction: the SAME row, delimited the pre-#1264 way, is still unparseable —
  // but it is now COUNTED, so scanLocal can disclose it (SB-SPLINTER-00) instead of shipping a
  // silently shorter advisor list. If this ever reads 0 while `rows` is empty, the row went
  // missing without a trace again, which is the whole defect.
  it("is counted, not silently dropped, when the same row arrives pipe-delimited", () => {
    const { rows, unparsedRows } = parseSplinterPipeText(PIPE_SEPARATED);
    expect(rows).toHaveLength(0);
    expect(unparsedRows).toBe(1);
    expect(parseSplinterOutput(PIPE_SEPARATED).unparsedRows).toBe(1);
  });

  it("counts nothing on the recorded all-clean fixture, so the count means what it says", () => {
    expect(parseSplinterOutput(FIXTURE_RAW).unparsedRows).toBe(0);
  });
});

describe("splinterRowsToAdvisorLints", () => {
  it("parses the Postgres array-literal categories field into a string array", () => {
    const [lint] = splinterRowsToAdvisorLints(parseSplinterPipeText(FIXTURE_RAW).rows);
    expect(lint?.categories).toEqual(["PERFORMANCE"]);
  });

  it("parses the JSON metadata field into an object", () => {
    const { rows } = parseSplinterPipeText(FIXTURE_RAW);
    const authUsersRow = rows.find((r) => r.name === "auth_users_exposed")!;
    const [lint] = splinterRowsToAdvisorLints([authUsersRow]);
    expect(lint?.metadata).toEqual({ name: "user_directory", type: "view", schema: "public", exposed_to: ["anon"] });
  });

  it("drops a row with unparseable metadata instead of throwing", () => {
    const [lint] = splinterRowsToAdvisorLints([
      { name: "x", title: "X", level: "INFO", metadata: "{not json" },
    ]);
    expect(lint?.metadata).toBeUndefined();
  });
});

describe("parseSplinterOutput -> parseAdvisorFindings — recorded connected-tier fixture", () => {
  it("surfaces every lint named in the dry-run-calibration.md §9 live confirmation", () => {
    const findings = parseAdvisorFindings(parseSplinterOutput(FIXTURE_RAW));
    const taxonomies = new Set(findings.map((f) => f.taxonomy));
    expect(taxonomies).toEqual(
      new Set([
        "unindexed_foreign_keys",
        "auth_users_exposed",
        "auth_rls_initplan",
        "unused_index",
        "rls_enabled_no_policy",
        "security_definer_view",
        "function_search_path_mutable",
        "rls_disabled_in_public",
        "rls_references_user_metadata",
        "anon_security_definer_function_executable",
        "authenticated_security_definer_function_executable",
      ]),
    );
  });

  it("marks every Splinter-sourced finding mechanical + high precision, same trust tier as a hosted advisor hit", () => {
    const findings = parseAdvisorFindings(parseSplinterOutput(FIXTURE_RAW));
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.mechanical && f.precisionTier === "high")).toBe(true);
  });

  it("curates rls_disabled_in_public to Critical and locates it at the exact table", () => {
    const findings = parseAdvisorFindings(parseSplinterOutput(FIXTURE_RAW));
    const finding = findings.find((f) => f.taxonomy === "rls_disabled_in_public");
    expect(finding?.severity).toBe("Critical");
    expect(finding?.location).toBe("public.audit_logs");
  });

  it("emits the 14 unindexed_foreign_keys rows the live confirmation caught", () => {
    const findings = parseAdvisorFindings(parseSplinterOutput(FIXTURE_RAW));
    expect(findings.filter((f) => f.taxonomy === "unindexed_foreign_keys")).toHaveLength(14);
  });
});

describe("runSplinter argv (#1297)", () => {
  afterEach(() => { vi.unstubAllEnvs(); });

  it.each([
    ["postgresql://app:dummy-pg-first@db1:5432,db2:5433/main?password=dummy-pg-second&password=", "postgresql://app@db1:5432,db2:5433/main", ""],
    ["host=db password=dummy-pg-first password=dummy-pg-second", "host=db", "dummy-pg-second"],
    ["postgresql:///main?host=%2Ftmp%2Fpg-socket&pass%77ord=dummy-pg-second", "postgresql:///main?host=%2Ftmp%2Fpg-socket", "dummy-pg-second"],
  ])("uses password transport at the shipping exec binding (#1778): %s", (input, clean, password) => {
    vi.stubEnv("PGPASSWORD", "dummy-inherited-pg");
    vi.mocked(execFileSync).mockClear().mockReturnValue("");
    expect(runSplinter(input).failure).toBeUndefined();
    const [file, argv, options] = vi.mocked(execFileSync).mock.calls[0] as [string, string[], { env: NodeJS.ProcessEnv }];
    expect(file).toBe("psql");
    expect(argv[0]).toBe(clean);
    expect(options.env.PGPASSWORD).toBe(password);
    expect(argv[argv.indexOf("-v") + 1]).toBe("ON_ERROR_STOP=1");
    expect(argv[argv.indexOf("-f") + 1]).toMatch(/splinter\.sql$/);
    expect(process.env.PGPASSWORD).toBe("dummy-inherited-pg");
  });

  it.each([
    "postgresql://app:dummy-canary@db/main?password=dummy-second&application_name=dummy-canary",
    "host=db password=dummy-canary password='' application_name=dummy-canary",
    "postgresql://db/main?password=dummy-canary%FF",
    "postgresql://db/main?password=dummy-canary%00",
    "host=db password='dummy-canary",
    "host=db oauth_client_secret=dummy-canary",
  ])("refuses malformed or still-exposed overridden credentials before exec (#1778): %s", (input) => {
    vi.mocked(execFileSync).mockClear();
    expect(() => runSplinter(input)).toThrow(SecretInArgvError);
    expect(() => runSplinter(input)).not.toThrow(/dummy-canary/);
    expect(execFileSync).not.toHaveBeenCalled();
  });

  it("keeps the client's database password out of argv and hands it to libpq via PGPASSWORD", () => {
    vi.mocked(execFileSync).mockReturnValue("");
    runSplinter("postgresql://postgres:not-a-real-db-password@db.abcxyz.supabase.co:5432/postgres");

    const [file, argv, opts] = vi.mocked(execFileSync).mock.calls.at(-1) as [string, string[], { env: NodeJS.ProcessEnv }];
    expect(file).toBe("psql");
    for (const arg of argv) expect(arg).not.toContain("not-a-real-db-password");
    expect(opts.env["PGPASSWORD"]).toBe("not-a-real-db-password");
    // The rest of the connection still has to reach psql, or the fix silently breaks the scan.
    expect(argv[0]).toContain("db.abcxyz.supabase.co:5432/postgres");
    expect(argv).toContain("-f");
  });

  // #1264 — the parser can only recover a piped identifier if psql was asked for a separator the
  // identifier will not contain. Revert this to "|" and the pipe-bearing lint above goes back to
  // being unparseable on every real local scan.
  it("asks psql for the unit separator, not the pipe", () => {
    vi.mocked(execFileSync).mockReturnValue("");
    runSplinter("postgresql://postgres@localhost:54322/postgres");

    const [, argv] = vi.mocked(execFileSync).mock.calls.at(-1) as [string, string[]];
    expect(argv[argv.indexOf("-F") + 1]).toBe("\u001f");
  });

  // #1755 — a script error must surface as a non-zero exit, or a fully-failed lint pass reads as
  // "0 advisories, clean". MEASURED 2026-07-31 (psql 18.4 / Postgres 16.14): WITHOUT this flag the
  // same failure exits 0.
  it("sets ON_ERROR_STOP=1 so a query error in splinter.sql cannot exit 0", () => {
    vi.mocked(execFileSync).mockReturnValue("");
    runSplinter("postgresql://postgres@localhost:54322/postgres");

    const [, argv] = vi.mocked(execFileSync).mock.calls.at(-1) as [string, string[]];
    expect(argv[argv.indexOf("-v") + 1]).toBe("ON_ERROR_STOP=1");
  });
});

// #1755 — the #1664/#1752 classification (execSemgrep/runOsvScanner) applied to psql: a run that
// did not complete must never be parsed as the advisor set, however plausible its caught stdout
// looks. Each thrown shape mirrors what execFileSync actually raises for that failure mode.
function execError(over: { status?: number | null; signal?: string | null; stdout?: string; code?: string }): Error {
  const err = new Error("Command failed: psql") as Error & { status: number | null; signal: string | null; stdout: string | undefined; code?: string };
  err.status = over.status ?? null;
  err.signal = over.signal ?? null;
  err.stdout = over.stdout;
  if (over.code) err.code = over.code;
  return err;
}

describe("runSplinter refuses an incomplete run (#1755)", () => {
  it("exit 3 (ON_ERROR_STOP script error) is a failure naming the exit code, even with plausible-looking partial stdout", () => {
    vi.mocked(execFileSync).mockImplementationOnce(() => {
      throw execError({ status: 3, stdout: "SET\nDO\n" });
    });
    const response = runSplinter("postgresql://postgres@localhost:54322/postgres");
    expect(response.failure).toBeDefined();
    expect(response.failure).toContain("exited with code 3");
    expect(response.lints).toEqual([]);
  });

  it("a signal-killed run (lost connection) is a failure naming the signal", () => {
    vi.mocked(execFileSync).mockImplementationOnce(() => {
      throw execError({ signal: "SIGTERM" });
    });
    const response = runSplinter("postgresql://postgres@localhost:54322/postgres");
    expect(response.failure).toContain("killed by signal SIGTERM");
    expect(response.lints).toEqual([]);
  });

  it("a missing psql binary is a failure, not an uncaught ENOENT", () => {
    vi.mocked(execFileSync).mockImplementationOnce(() => {
      throw execError({ code: "ENOENT" });
    });
    const response = runSplinter("postgresql://postgres@localhost:54322/postgres");
    expect(response.failure).toBe("psql not found on PATH");
  });

  it("a completed run (exit 0) still parses and reports no failure", () => {
    vi.mocked(execFileSync).mockReturnValueOnce(FIXTURE_RAW);
    const response = runSplinter("postgresql://postgres@localhost:54322/postgres");
    expect(response.failure).toBeUndefined();
    expect(response.lints.length).toBeGreaterThan(0);
  });
});
