import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import postgres from "postgres";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildHtml } from "../report-template/render.mjs";
import { conservationLedger } from "./conservation-ledger.js";
import { type Finding, type FindingsDocument, type ReportMeta, validateFindings } from "./findings.js";
import { renderFidelityBreaches } from "./render-fidelity.js";
import { toSarif } from "./sarif.js";
import { AUDIT_MODULES } from "./audit-coverage.js";
import { runAudit, type ProbeResult } from "./audit-runner.js";
import { AUDIT_RUNNERS } from "./audit-runners.js";
import { createAuditReplayBinding, replayAuditBundle, writeAuditReplayBundle } from "./audit-replay.js";
import { deliverAuditReplay } from "./audit-replay-delivery.js";

const execute = promisify(execFile);
const META: ReportMeta = { client: "M10 synthetic fixture", subtitle: "Catalog-only protection review", date: "2026-09-25", commit: "fixture", auditor: "Harvey", confidential: false, overallHealth: 6, tenantIsolation: "Review", authModel: "PostgreSQL roles/RLS", headline: "Sensitivity and protection evidence", scope: "Local disposable PostgreSQL; no production rows", methodology: "Catalog queries plus independent synthetic controls", outOfScope: "Live clients, storage controls and complete source crypto proof" };
// The opt-in owns a fresh socket-only synthetic cluster and ignores connection URLs.
// Recorded catalog tests cover the same producer on hosts without PostgreSQL binaries.
describe.runIf(process.env.HARVEY_M10_POSTGRES_TESTS === "1")("M10 actual PostgreSQL and shipping delivery", () => {
  let root = "";
  let started = false;
  let sql: ReturnType<typeof postgres>;
  const binary = (name: string) => process.env.HARVEY_M10_PG_BIN ? join(process.env.HARVEY_M10_PG_BIN, name) : name;
  const evidence = process.env.HARVEY_M10_EVIDENCE_DIR;
  const observations: unknown[] = [];
  beforeAll(async () => {
    root = mkdtempSync("/tmp/harvey-m10-test-");
    mkdirSync(join(root, "socket"));
    await execute(binary("initdb"), ["-D", join(root, "data"), "-U", "harvey_fixture", "--auth-local=trust", "--auth-host=reject", "--no-locale", "--encoding=UTF8"]);
    await execute(binary("pg_ctl"), ["-D", join(root, "data"), "-l", join(root, "postgres.log"), "-o", `-k ${join(root, "socket")} -c listen_addresses='' -p 55439`, "-w", "start"]);
    started = true;
    sql = postgres({ host: join(root, "socket"), port: 55439, username: "harvey_fixture", database: "postgres", max: 1, onnotice() {} });
    await sql.unsafe(readFileSync(new URL("./scan/__fixtures__/m10-protection/schema.sql", import.meta.url), "utf8"));
    if (evidence) mkdirSync(evidence, { recursive: true });
  });
  afterAll(async () => {
    if (sql) await sql.end();
    if (started) await execute(binary("pg_ctl"), ["-D", join(root, "data"), "-m", "fast", "-w", "stop"]);
    if (root) rmSync(root, { recursive: true, force: true });
  });

  async function countAs(role: string, query: string) {
    await sql.unsafe(`set role ${role}`);
    try {
      await sql.unsafe("set fixture.tenant='a'");
      const count = (await sql.unsafe(query)).length;
      observations.push({ role, query, count });
      return count;
    } catch (error) {
      observations.push({ role, query, denied: true });
      throw error;
    } finally { await sql.unsafe("reset role"); }
  }
  async function run(schemas: string, name: string, extra: string[] = []) {
    const out = join(root, `${name}.json`);
    const map = join(root, `${name}-map.json`);
    const env = { ...process.env, SUPABASE_DB_URL: "postgres:///postgres", PGHOST: join(root, "socket"), PGPORT: "55439", PGUSER: "harvey_fixture", PGDATABASE: "postgres" };
    const result = await execute(process.execPath, ["--import", "tsx", "tools/pii-classify.mjs", "--schemas", schemas, "--exposed-schemas", "public,private,pgtenant", "--out", out, "--data-map-out", map, ...extra], { env, maxBuffer: 8 * 1024 * 1024 });
    const findings = JSON.parse(readFileSync(out, "utf8")) as Finding[];
    if (evidence) {
      writeFileSync(join(evidence, `${name}-findings.json`), JSON.stringify(findings, null, 2));
      writeFileSync(join(evidence, `${name}-map.json`), readFileSync(map));
      writeFileSync(join(evidence, `${name}-stdout.log`), result.stdout);
    }
    return findings;
  }

  it("pairs exact column grants and row policies with independent actual synthetic queries", async () => {
    expect(await countAs("anon", "select nickname from private.patient")).toBe(1);
    await expect(countAs("anon", "select ssn from private.patient")).rejects.toThrow(/permission denied/);
    expect(await countAs("anon", "select ssn from private.patient_open")).toBe(1);
    await expect(countAs("anon", "select nickname from private.patient_open")).rejects.toThrow(/permission denied/);
    expect(await countAs("anon", "select ssn from private.patient_rls")).toBe(0);
    expect(await countAs("anon", "select ssn from private.patient_conditional")).toBe(1);
    expect(await countAs("anon", "select ssn from private.patient_view")).toBe(1);
    const findings = await run("public, private ,pgtenant", "all-schemas");
    const protection = findings.filter((f) => f.id.startsWith("M10-PII-"));
    expect(protection.map((f) => f.location).sort()).toEqual(["pgtenant.customer.ssn", "private.encrypted_patient.ssn", "private.patient_conditional.ssn", "private.patient_open.ssn", "private.patient_view.ssn", "public.contacts.email"]);
    expect(protection.find((f) => f.location === "private.patient_open.ssn")).toMatchObject({ severity: "High", precisionTier: "review" });
    expect(protection.find((f) => f.location === "public.contacts.email")).toMatchObject({ severity: "Medium", precisionTier: "review" });
    expect(protection.find((f) => f.location === "private.patient_conditional.ssn")!.evidence).toContain("SELECT=conditional");
    if (evidence) writeFileSync(join(evidence, "runtime-controls.json"), JSON.stringify(observations, null, 2));
  });

  it("delivers the real CLI population and limitations through report, JSON and SARIF", async () => {
    const findings = await run("public,private,pgtenant", "delivery");
    const doc: FindingsDocument = {
      meta: META,
      findings,
    };
    expect(validateFindings(doc)).toEqual({ ok: true, errors: [] });
    const html = buildHtml(doc);
    expect(renderFidelityBreaches(doc, html)).toEqual([]);
    for (const text of ["examined 3 schema(s), 8 relation(s), 11 column(s)", "unexamined 1 schema(s), 1 relation(s), 1 column(s)", "absence does not establish plaintext", "database.encryption-boundaries", "Source encryption boundaries unassessed", "private.patient_open.ssn"]) expect(html).toContain(text);
    const sarif = toSarif(findings, { coverageAbsent: "Focused synthetic M10 validation; other audit modules were not run." }) as { runs: { results: unknown[] }[] };
    expect(sarif.runs[0]!.results).toHaveLength(findings.length);
    const json = JSON.parse(JSON.stringify(doc)) as FindingsDocument;
    const ledger = conservationLedger(findings, json.findings, { M10: findings });
    expect(ledger).toMatchObject({ ok: true, produced: 15, delivered: 15, unaccounted: 0, suppressed: 0, capped: 0, deduped: 0 });
    if (evidence) {
      writeFileSync(join(evidence, "document.json"), JSON.stringify(json, null, 2));
      writeFileSync(join(evidence, "report.html"), html);
      writeFileSync(join(evidence, "report.sarif"), JSON.stringify(sarif, null, 2));
      writeFileSync(join(evidence, "conservation.json"), JSON.stringify(ledger, null, 2));
    }
  });

  it("retains protection review for a real ciphertext control and integrity-bound source evidence", async () => {
    const file = join(root, "encrypt.mjs");
    const source = readFileSync(new URL("./scan/__fixtures__/m10-protection/encrypt-patient.mjs.txt", import.meta.url));
    writeFileSync(file, source);
    const { encryptPatient } = await import(/* @vite-ignore */ pathToFileURL(file).href);
    const ciphertext = await encryptPatient("synthetic-ssn") as Uint8Array;
    expect(Buffer.from(ciphertext).equals(Buffer.from("synthetic-ssn"))).toBe(false);
    expect(ciphertext.length).toBeGreaterThan(Buffer.byteLength("synthetic-ssn"));
    await sql`update private.encrypted_patient set ssn=${Buffer.from(ciphertext)}`;
    const manifest = join(root, "boundaries.json");
    writeFileSync(manifest, JSON.stringify([{ schema: "private", table: "encrypted_patient", column: "ssn", path: "encrypt.mjs", line: 2, sha256: createHash("sha256").update(source).digest("hex") }]));
    const rows = await run("public,private,pgtenant", "source-boundary", ["--source-root", root, "--encryption-boundaries", manifest]);
    expect(rows.find((f) => f.id === "M10-PROT-00")!.evidence).toContain("1 source reference(s) checked against file bytes");
    expect(rows.find((f) => f.id.startsWith("M10-PII-") && f.location === "private.encrypted_patient.ssn")!.evidence).toContain("remain unverified");
    writeFileSync(file, "// Changed source, retaining the referenced line.\nexport const encryptPatient = value => value;\n");
    const changed = await run("public,private,pgtenant", "source-mismatch", ["--source-root", root, "--encryption-boundaries", manifest]);
    expect(changed.find((f) => f.id === "M10-PROT-00")!.evidence).toContain("did not match file bytes");
    if (evidence) writeFileSync(join(evidence, "ciphertext-control.json"), JSON.stringify({ plaintextBytes: Buffer.byteLength("synthetic-ssn"), ciphertextBytes: ciphertext.length, differs: true, sourceSha256: createHash("sha256").update(source).digest("hex"), findingRemainsReview: true, changedSourceRejected: true }, null, 2));
  });

  it("reports non-public unexamined populations when authorization selects only public", async () => {
    const findings = await run("public", "public-only");
    expect(findings.filter((f) => f.id.startsWith("M10-PII-")).map((f) => f.location)).toEqual(["public.contacts.email"]);
    expect(findings.find((f) => f.id === "M10-PROT-00")!.evidence).toContain("unexamined 3 schema(s), 8 relation(s), 11 column(s)");
  });
  it("delivers unavailable metadata and unknown denominators after real catalog permission errors", async () => {
    await sql.unsafe("create role m10_catalog_limited login");
    await sql.unsafe("revoke select on pg_catalog.pg_attribute from public");
    try {
      const out = join(root, "unavailable.json");
      let failedOutput = "";
      await expect(execute(process.execPath, ["--import", "tsx", "tools/pii-classify.mjs", "--schemas", "public,private", "--exposed-schemas", "public,private", "--out", out], {
        env: { ...process.env, SUPABASE_DB_URL: "postgres:///postgres", PGHOST: join(root, "socket"), PGPORT: "55439", PGUSER: "m10_catalog_limited", PGDATABASE: "postgres" }, maxBuffer: 8 * 1024 * 1024,
      }).catch((error: { code: number; stdout: string }) => { failedOutput = error.stdout; throw error; })).rejects.toMatchObject({ code: 1 });
      const rows = JSON.parse(readFileSync(out, "utf8")) as Finding[];
      expect(rows).toHaveLength(1);
      expect(rows[0]!.id).toBe("M10-PROT-00");
      expect(rows[0]!.evidence).toContain("unexamined unknown schema(s), unknown relation(s), unknown column(s)");
      expect(rows[0]!.evidence).toContain("query failed");
      expect(rows[0]!.evidence).toContain("no absence or clean result is inferred");
      const target = join(root, "target"); mkdirSync(target); writeFileSync(join(target, "schema.sql"), "create table synthetic (email text);");
      const context = { targetDir: target, env: { connected: true, dynamic: false, llm: false }, captureDir: root, exists: () => true, exec: () => ({ ok: false, output: failedOutput }), readFindings: () => rows };
      const report = AUDIT_RUNNERS.find((r) => r.module === "M10")!.run(context) as ProbeResult;
      expect(report).toMatchObject({ kind: "not-assessed", findings: rows });
      const fresh = runAudit(AUDIT_MODULES.map((module) => ({ module, producers: [], typed: true as const, run: () => module === "M10" ? report : { kind: "not-assessed" as const, reason: "outside focused synthetic fixture", provenance: "MEASURED" as const, falsifier: "run this module separately" } })), context);
      expect(fresh.findingsByModule.M10).toEqual(rows);
      const direct = { meta: META, findings: fresh.findings };
      expect(buildHtml(direct)).toContain("unexamined unknown schema(s)");
      expect(conservationLedger(rows, fresh.findings)).toMatchObject({ ok: true, produced: 1, delivered: 1, unaccounted: 0 });
      const bundle = join(root, "bundle");
      const scope = { module: "M10" as const, workspace: ".", tier: "connected", surface: "catalog", wholeModule: true };
      writeAuditReplayBundle(bundle, { binding: createAuditReplayBinding(target, { schemas: ["public", "private"], sampling: false }), scopes: [scope], passes: [{ scope, generatedAt: new Date().toISOString(), producer: { name: "pii-classify", version: "synthetic-catalog-fixture" }, result: report, rawArtifacts: [out] }], meta: META });
      const replay = replayAuditBundle(bundle, target);
      expect(replay.result.recorded.find((r) => r.module === "M10")).toMatchObject({ status: "requires-live-run" });
      expect(replay.result.findingsByModule.M10).toEqual(rows);
      const owner = replay.evidence.findingOwners.find((r) => r.id === "M10-PROT-00")!;
      expect(owner.receipts).toEqual([replay.evidence.current[0]!.id]);
      expect(owner.rawArtifacts[0]!.sha256).toBe(createHash("sha256").update(readFileSync(out)).digest("hex"));
      const destination = evidence ?? root;
      await deliverAuditReplay({ target, bundle, findingsOut: join(destination, "catalog-denied-document.json"), htmlOut: join(destination, "catalog-denied-report.html"), conservationOut: join(destination, "catalog-denied-conservation.json") });
      expect(readFileSync(join(destination, "catalog-denied-report.html"), "utf8")).toContain("unexamined unknown schema(s)");
      expect(JSON.parse(readFileSync(join(destination, "catalog-denied-conservation.json"), "utf8"))).toMatchObject({ ok: true, produced: 1, delivered: 2, deliveredFromProduced: 1, synthesized: 1, unaccounted: 0 });
      if (evidence) {
        writeFileSync(join(evidence, "catalog-denied-findings.json"), JSON.stringify(rows, null, 2));
        writeFileSync(join(evidence, "catalog-denied-original-report.json"), JSON.stringify(report, null, 2));
        writeFileSync(join(evidence, "catalog-denied-replay-ownership.json"), JSON.stringify(replay.evidence, null, 2));
      }
    } finally { await sql.unsafe("grant select on pg_catalog.pg_attribute to public"); }
  });

});
