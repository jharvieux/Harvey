import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { CoverageRow, Finding } from "./findings.js";
import { parseLocation, toSarif } from "./sarif.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "F-01",
    title: "Service-role key in client bundle",
    severity: "Critical",
    confidence: "Confirmed",
    category: "Secret exposure",
    taxonomy: "secret_service_role_client",
    location: "src/lib/client.ts:12",
    status: "Open",
    evidence: "decoded JWT role=service_role",
    impact: "bypasses all RLS",
    fix: "move the key server-side",
    value: 5, ease: 4, safety: 5,
    ...over,
  };
}

const RAN: CoverageRow[] = [{ module: "M1", name: "Multi-tenant security", status: "ran" }];

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- SARIF is emitted as plain JSON; the tests read it the way a consumer would.
const run = (log: object): any => (log as any).runs[0];

describe("result mapping", () => {
  it("uses the taxonomy as the rule id and severity as the level", () => {
    const r = run(toSarif([finding(), finding({ severity: "Medium", taxonomy: "perf_n_plus_one" })], { coverage: RAN }));
    expect(r.results.map((x: { ruleId: string; level: string }) => [x.ruleId, x.level])).toEqual([
      ["secret_service_role_client", "error"],
      ["perf_n_plus_one", "warning"],
    ]);
    expect(r.tool.driver.rules.map((x: { id: string }) => x.id)).toEqual(["secret_service_role_client", "perf_n_plus_one"]);
  });

  it("declares each rule once even when many findings share it", () => {
    const r = run(toSarif([finding(), finding({ id: "F-02", location: "src/other.ts:3" })], { coverage: RAN }));
    expect(r.results).toHaveLength(2);
    expect(r.tool.driver.rules).toHaveLength(1);
  });

  it("fingerprints on the same identity audit-diff uses, so a line shift stays one alert", () => {
    const a = run(toSarif([finding({ location: "src/lib/client.ts:12" })], { coverage: RAN }));
    const b = run(toSarif([finding({ location: "src/lib/client.ts:97" })], { coverage: RAN }));
    expect(a.results[0].partialFingerprints).toEqual(b.results[0].partialFingerprints);
  });

  it("fingerprints root, separator, dot, and symlink aliases equally while preserving case policy", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-sarif-identity-"));
    try {
      mkdirSync(join(root, "src"), { recursive: true });
      writeFileSync(join(root, "src", "a.ts"), "export {}\n");
      symlinkSync("src/a.ts", join(root, "alias.ts"));
      const fingerprint = (location: string, caseSensitive = true) => run(toSarif(
        [finding({ location })],
        { coverage: RAN },
        { baseUri: root, caseSensitive },
      )).results[0].partialFingerprints;
      const equivalent = [
        "src/a.ts:7", "./src//a.ts:19", "src\\.\\a.ts#L42",
        join(root, "src", "a.ts") + ":88", "alias.ts:3",
      ];
      expect(new Set(equivalent.map((location) => JSON.stringify(fingerprint(location)))).size).toBe(1);
      expect(fingerprint("src/Foo.ts", true)).not.toEqual(fingerprint("src/foo.ts", true));
      expect(fingerprint("src/Foo.ts", false)).toEqual(fingerprint("src/foo.ts", false));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("ranks alerts for code scanning by carrying security-severity per rule", () => {
    const r = run(toSarif([finding({ severity: "Critical" }), finding({ id: "F-02", severity: "Low", taxonomy: "t2" })], { coverage: RAN }));
    const sev = r.tool.driver.rules.map((x: { properties: Record<string, string> }) => x.properties["security-severity"]);
    expect(Number(sev[0])).toBeGreaterThan(Number(sev[1]));
  });

  it("exports non-security observations rather than dropping them", () => {
    const r = run(toSarif([finding({ severity: "Info", taxonomy: "dep_cve" })], { coverage: RAN }));
    expect(r.results).toHaveLength(1);
    expect(r.results[0].level).toBe("note");
  });
});

describe("locations", () => {
  it("parses the location shapes the scanners actually emit", () => {
    expect(parseLocation("src/a.ts:42")).toEqual({ uri: "src/a.ts", startLine: 42 });
    expect(parseLocation("[source] .env:9")).toEqual({ uri: ".env", startLine: 9 });
    expect(parseLocation("src/a.ts:42:7")).toEqual({ uri: "src/a.ts", startLine: 42, startColumn: 7 });
    expect(parseLocation("src/a.ts:10-20")).toEqual({ uri: "src/a.ts", startLine: 10, endLine: 20 });
    expect(parseLocation("package-lock.json (lodash@4.17.11)")).toEqual({ uri: "package-lock.json" });
  });

  it("refuses to invent a file URI for a location that is not a file", () => {
    expect(parseLocation("main DB (multiple tables)")).toBeUndefined();
    expect(parseLocation("(repo-wide)")).toBeUndefined();
  });

  it("makes URIs repo-relative so an alert can attach to a file", () => {
    const r = run(toSarif([finding({ location: "/tmp/target/src/a.ts:4" })], { coverage: RAN }, { baseUri: "/tmp/target" }));
    expect(r.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe("src/a.ts");
  });

  it("keeps a non-file finding as a result and says where it is, loudly", () => {
    const r = run(toSarif([finding({ location: "main DB (multiple tables)" })], { coverage: RAN }));
    expect(r.results).toHaveLength(1);
    expect(r.results[0].locations).toBeUndefined();
    expect(r.results[0].message.text).toContain("main DB (multiple tables)");
    expect(r.results[0].properties.location).toBe("main DB (multiple tables)");
    const notes = r.invocations[0].toolExecutionNotifications;
    expect(notes.some((n: { descriptor: { id: string } }) => n.descriptor.id === "harvey/location/non-file")).toBe(true);
  });
});

// The core of #867: SARIF's failure mode is that "no results" reads as "nothing wrong". A module
// that did not run must be as visible in the export as it is in the report.
describe("coverage ledger — a module that did not run cannot vanish", () => {
  const ledger: CoverageRow[] = [
    { module: "M1", name: "Multi-tenant security", status: "ran" },
    { module: "M2", name: "Local pen-test", status: "requires-live-run", reason: "no local Supabase stack in scope" },
    { module: "M8", name: "Test quality", status: "partial", reason: "Stryker dry run failed", subStatus: "sub-step-blocked" },
  ];

  it("emits one warning notification per module that did not fully run", () => {
    const notes = run(toSarif([], { coverage: ledger })).invocations[0].toolExecutionNotifications;
    const gaps = notes.filter((n: { descriptor: { id: string } }) => n.descriptor.id === "harvey/coverage/not-run");
    expect(gaps).toHaveLength(2);
    expect(gaps.every((n: { level: string }) => n.level === "warning")).toBe(true);
    expect(gaps.map((n: { properties: { module: string } }) => n.properties.module)).toEqual(["M2", "M8"]);
  });

  it("carries the reason, not just the status — a gap without one is a silent skip", () => {
    const notes = run(toSarif([], { coverage: ledger })).invocations[0].toolExecutionNotifications;
    expect(notes[0].message.text).toContain("no local Supabase stack in scope");
    expect(notes[1].message.text).toContain("Stryker dry run failed");
  });

  it("also carries the ledger verbatim for consumers that ignore notifications", () => {
    expect(run(toSarif([], { coverage: ledger })).properties.harveyCoverage).toEqual(ledger);
  });

  it("stays quiet only when every module actually ran", () => {
    expect(run(toSarif([], { coverage: RAN })).invocations[0].toolExecutionNotifications).toEqual([]);
  });

  it("a ledgerless export must state its scope — there is no silent path", () => {
    const r = run(toSarif([], { coverageAbsent: "mechanical tier only; nine modules not attempted" }));
    const note = r.invocations[0].toolExecutionNotifications[0];
    expect(note.descriptor.id).toBe("harvey/coverage/absent");
    expect(note.level).toBe("warning");
    expect(note.message.text).toContain("nine modules not attempted");
    expect(r.properties.harveyCoverageAbsent).toContain("mechanical tier only");
  });
});

describe("document shape", () => {
  it("is a SARIF 2.1.0 log with declared notification descriptors", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- reading the emitted JSON as a consumer would
    const log = toSarif([finding()], { coverage: RAN }) as any;
    expect(log.version).toBe("2.1.0");
    expect(log.$schema).toContain("sarif-schema-2.1.0");
    expect(log.runs[0].tool.driver.name).toBe("Harvey");
    const declared = log.runs[0].tool.driver.notifications.map((n: { id: string }) => n.id);
    expect(declared).toContain("harvey/coverage/not-run");
    expect(declared).toContain("harvey/coverage/absent");
  });
});

describe("#975: CWE tags a CWE-indexed consumer can read", () => {
  it("emits both the machine external/cwe/cwe-NNN tag and the human CWE string", () => {
    const r = run(toSarif([finding({ cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"], owasp: ["A03:2021 - Injection"] })], { coverage: RAN }));
    const tags = r.tool.driver.rules[0].properties.tags as string[];
    expect(tags).toContain("external/cwe/cwe-89");
    expect(tags).toContain("CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')");
    expect(tags).toContain("A03:2021 - Injection");
  });

  it("emits a machine tag for every CWE when a finding carries several", () => {
    const r = run(toSarif([finding({ cwe: ["CWE-79: XSS", "CWE-116: Improper Encoding or Escaping of Output"] })], { coverage: RAN }));
    const tags = r.tool.driver.rules[0].properties.tags as string[];
    expect(tags).toContain("external/cwe/cwe-79");
    expect(tags).toContain("external/cwe/cwe-116");
  });

  it("omits CWE tags entirely for a finding with no CWE (no empty/garbage tag)", () => {
    const r = run(toSarif([finding({ cwe: undefined })], { coverage: RAN }));
    const tags = r.tool.driver.rules[0].properties.tags as string[];
    expect(tags.some((t) => t.startsWith("external/cwe/"))).toBe(false);
  });

  it("#976: tolerates a bare-STRING cwe/owasp without throwing (registry rules ship both shapes)", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Finding.cwe is typed string[] but real inputs can carry a bare string
    const r = run(toSarif([finding({ cwe: "CWE-89: SQL Injection" as any, owasp: "A03:2021 - Injection" as any })], { coverage: RAN }));
    const tags = r.tool.driver.rules[0].properties.tags as string[];
    expect(tags).toContain("external/cwe/cwe-89");
    expect(tags).toContain("CWE-89: SQL Injection");
    expect(tags).toContain("A03:2021 - Injection");
  });
});
