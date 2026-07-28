import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
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
    const rows = parseSplinterPipeText(FIXTURE_RAW);
    expect(rows).toHaveLength(33);
    expect(rows.every((r) => r.name && r.title && r.level)).toBe(true);
  });

  it("returns nothing for text with no valid 10-column rows", () => {
    expect(parseSplinterPipeText("psql:foo.sql:1: WARNING: bla\nSET\nDO\n\n")).toEqual([]);
  });
});

describe("splinterRowsToAdvisorLints", () => {
  it("parses the Postgres array-literal categories field into a string array", () => {
    const [lint] = splinterRowsToAdvisorLints(parseSplinterPipeText(FIXTURE_RAW));
    expect(lint?.categories).toEqual(["PERFORMANCE"]);
  });

  it("parses the JSON metadata field into an object", () => {
    const rows = parseSplinterPipeText(FIXTURE_RAW);
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
});
