import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildHtml } from "../../report-template/render.mjs";
import { esc } from "../../report-template/sections.mjs";
import { renderFidelityBreaches } from "../render-fidelity.js";
import { dedupeAutoExposed, hasPgGraphql, parseExposedSchemas, probeExposedSchemas, runSupabaseScan } from "./supabase.js";
import { checkGraphqlIntrospection } from "./supabase-config.js";
import { mechanicalFinding } from "./common.js";
import type { FindingsDocument, ReportMeta } from "../findings.js";

const RENDER_META: ReportMeta = {
  client: "Acme", subtitle: "Supabase pass", date: "2026-07-30", commit: "abc1234", auditor: "Harvey",
  confidential: true, overallHealth: 6, tenantIsolation: "Not verified", authModel: "Supabase",
  headline: "Supabase local scan", scope: "the local stack", methodology: "M1", outOfScope: "infrastructure",
};

// #1494 — mutable per-test so the graphql-introspection wiring (which depends on pg_graphql being
// in pg_extension) can be exercised without a second postgres mock; reset in afterEach below.
const { mockExtensions } = vi.hoisted(() => ({
  mockExtensions: { value: [{ name: "pg_net", schema: "extensions", installed_version: "0.20.3" }] as unknown[] },
}));

vi.mock("postgres", () => ({
  default: vi.fn(() => ({
    unsafe: vi.fn(async (query: string) => {
      if (query.includes("realtime")) return [{ rlsEnabled: true }];
      if (query.includes("extensionOwned")) return [];
      if (query.includes("policyname")) return [];
      if (query.includes("pg_tables")) return [{ schema: "public", name: "widgets", rlsEnabled: false }];
      if (query.includes("pg_extension")) return mockExtensions.value;
      if (query.includes("storage.buckets")) return [{ id: "b1", name: "avatars", public: true }];
      if (query.includes("pg_policies")) return [];
      if (query.includes("pg_default_acl")) return [];
      if (query.includes("pg_attribute")) return [];
      if (query.includes("nspname = 'cron'")) return [{ exists: false }];
      if (query.includes("cron.job")) return [];
      if (query.includes("prosecdef")) return [];
      return [];
    }),
    end: vi.fn(async () => {}),
  })),
}));

function mockFetch(responses: {
  advisors: unknown;
  authConfig: unknown;
  tables: unknown;
  extensions: unknown;
  buckets: unknown;
  policies: unknown;
  realtime?: unknown;
  postgrest?: unknown;
  defaultAcl?: unknown;
  columnGrants?: unknown;
  cronSchemaExists?: boolean;
  cronJobs?: unknown;
  definerFunctions?: unknown;
  driftTables?: unknown;
  driftPolicies?: unknown;
}): typeof fetch {
  return vi.fn(async (url: string | URL, init?: RequestInit) => {
    const u = url.toString();
    if (u.includes("/advisors/security")) return new Response(JSON.stringify(responses.advisors));
    if (u.includes("/config/auth")) return new Response(JSON.stringify(responses.authConfig));
    if (u.includes("/postgrest")) return new Response(JSON.stringify(responses.postgrest ?? { db_schema: "public,graphql_public" }));
    if (u.includes("/database/query")) {
      const body = JSON.parse(String(init?.body ?? "{}")) as { query: string };
      if (body.query.includes("realtime")) return new Response(JSON.stringify(responses.realtime ?? [{ rlsEnabled: true }]));
      if (body.query.includes("extensionOwned")) return new Response(JSON.stringify(responses.driftTables ?? []));
      if (body.query.includes("policyname")) return new Response(JSON.stringify(responses.driftPolicies ?? []));
      if (body.query.includes("pg_tables")) return new Response(JSON.stringify(responses.tables));
      if (body.query.includes("pg_extension")) return new Response(JSON.stringify(responses.extensions));
      if (body.query.includes("storage.buckets")) return new Response(JSON.stringify(responses.buckets));
      if (body.query.includes("pg_policies")) return new Response(JSON.stringify(responses.policies));
      if (body.query.includes("pg_default_acl")) return new Response(JSON.stringify(responses.defaultAcl ?? []));
      if (body.query.includes("pg_attribute")) return new Response(JSON.stringify(responses.columnGrants ?? []));
      if (body.query.includes("nspname = 'cron'")) return new Response(JSON.stringify([{ exists: responses.cronSchemaExists ?? false }]));
      if (body.query.includes("cron.job")) return new Response(JSON.stringify(responses.cronJobs ?? []));
      if (body.query.includes("prosecdef")) return new Response(JSON.stringify(responses.definerFunctions ?? []));
    }
    return new Response("not found", { status: 404 });
  }) as unknown as typeof fetch;
}

// #1494 — the shape PostgREST answers with for a schema no target defines: PGRST106, with the full
// exposed-schema allow-list in `hint`. Real shape captured live 2026-07-28 against the calibration
// stack (src/cli/validate-connected.ts).
function restProbeFetch(schemas: string): typeof fetch {
  return vi.fn(async () => new Response(JSON.stringify({ code: "PGRST106", hint: `Only the following schemas are exposed: ${schemas}` }), { status: 406 })) as unknown as typeof fetch;
}

afterEach(() => {
  mockExtensions.value = [{ name: "pg_net", schema: "extensions", installed_version: "0.20.3" }];
});

describe("runSupabaseScan", () => {
  it("throws when neither projectRef nor local is given", async () => {
    await expect(runSupabaseScan({ managementApiToken: "t" })).rejects.toThrow(/requires projectRef/);
  });

  it("throws when no Management API token is available", async () => {
    await expect(runSupabaseScan({ projectRef: "abc", managementApiToken: "" })).rejects.toThrow(/token required/);
  });

  it("merges advisor, auth-config, table, extension, and bucket findings from a hosted scan", async () => {
    const fetchImpl = mockFetch({
      advisors: { lints: [{ name: "rls_disabled_in_public", title: "RLS Disabled in Public", level: "ERROR", metadata: { name: "orders", schema: "public" } }] },
      authConfig: { mailer_autoconfirm: true },
      tables: [{ schema: "public", name: "widgets", rlsEnabled: false }],
      extensions: [{ name: "pg_net", schema: "extensions", installed_version: "0.20.3" }],
      buckets: [{ id: "b1", name: "avatars", public: true }],
      policies: [],
    });

    const findings = await runSupabaseScan({ projectRef: "abc123", managementApiToken: "t", fetchImpl });
    const taxonomies = findings.map((f) => f.taxonomy);

    expect(taxonomies).toContain("rls_disabled_in_public");
    expect(taxonomies).toContain("Auth config: email confirmation disabled");
    expect(taxonomies).toContain("Auto-exposed public-schema table");
    expect(taxonomies).toContain("Dangerous extension enabled");
    expect(taxonomies).toContain("Public bucket with no policies");
    expect(findings.every((f) => f.mechanical)).toBe(true);
  });

  // #1098 — the check read `otp_expiry`, the CLI config.toml key, which /config/auth never emits, so
  // the finding could not reach a real engagement no matter how green the unit test was. This asserts
  // the whole hosted seam on the API's own spelling, and that the config.toml spelling yields nothing.
  it("raises the long-OTP finding from the API's mailer_otp_exp, not the config.toml otp_expiry", async () => {
    const hosted = async (authConfig: unknown) =>
      runSupabaseScan({
        projectRef: "abc123",
        managementApiToken: "t",
        fetchImpl: mockFetch({ advisors: { lints: [] }, authConfig, tables: [], extensions: [], buckets: [], policies: [] }),
      });

    const fromApiShape = await hosted({ mailer_otp_exp: 86400, external_email_enabled: true });
    const otp = fromApiShape.find((f) => f.taxonomy === "Auth config: long OTP expiry")!;
    expect(otp.severity).toBe("Low");
    expect(otp.evidence).toContain("mailer_otp_exp=86400");

    const fromTomlShape = await hosted({ otp_expiry: 86400, external_email_enabled: true });
    expect(fromTomlShape.map((f) => f.taxonomy)).not.toContain("Auth config: long OTP expiry");
  });

  it("runs the connected-tier checks (realtime, exposed schema, pg_graphql) on a hosted scan", async () => {
    const fetchImpl = mockFetch({
      advisors: { lints: [] },
      authConfig: {},
      tables: [],
      extensions: [{ name: "pg_graphql", schema: null, installed_version: "1.5.11" }],
      buckets: [],
      policies: [],
      realtime: [{ rlsEnabled: false }],
      postgrest: { db_schema: "public,graphql_public,internal" },
    });
    const taxonomies = (await runSupabaseScan({ projectRef: "abc123", managementApiToken: "t", fetchImpl })).map((f) => f.taxonomy);
    expect(taxonomies).toContain("Realtime channel lacks authorization");
    expect(taxonomies).toContain("PostgREST schema exposure wider than intended");
    expect(taxonomies).toContain("pg_graphql introspection enabled in production");
  });

  it("probes a self-hosted GoTrue endpoint for the vulnerable-version classes", async () => {
    const fetchImpl = vi.fn(async (url: string | URL) => {
      const u = url.toString();
      if (u.endsWith("/health")) return new Response(JSON.stringify({ version: "v2.100.0" }));
      if (u.endsWith("/settings")) return new Response(JSON.stringify({ external: { apple: true, azure: false } }));
      if (u.includes("/advisors/security")) return new Response(JSON.stringify({ lints: [] }));
      if (u.includes("/config/auth")) return new Response(JSON.stringify({}));
      if (u.includes("/postgrest")) return new Response(JSON.stringify({ db_schema: "public" }));
      if (u.includes("/database/query")) return new Response(JSON.stringify([]));
      return new Response("not found", { status: 404 });
    }) as unknown as typeof fetch;
    const taxonomies = (
      await runSupabaseScan({ projectRef: "abc123", managementApiToken: "t", fetchImpl, gotrueProbe: { authUrl: "https://self-hosted.example.com/auth/v1", anonKey: "anon" } })
    ).map((f) => f.taxonomy);
    expect(taxonomies).toContain("Self-hosted GoTrue OIDC issuer bypass"); // 2.100.0 < 2.185.0 with Apple enabled
    expect(taxonomies).toContain("Self-hosted GoTrue email-link poisoning"); // within 2.67.1–2.163.0
  });

  it("propagates a Management API error instead of swallowing it", async () => {
    const fetchImpl = vi.fn(async () => new Response("forbidden", { status: 403 })) as unknown as typeof fetch;
    await expect(runSupabaseScan({ projectRef: "abc123", managementApiToken: "t", fetchImpl })).rejects.toThrow(/403/);
  });

  describe("pg_cron wiring", () => {
    it("does not query cron.job and reports no pg_cron findings when the cron schema is absent (N/A)", async () => {
      const fetchImpl = mockFetch({
        advisors: { lints: [] },
        authConfig: {},
        tables: [],
        extensions: [],
        buckets: [],
        policies: [],
        cronSchemaExists: false,
      });
      const findings = await runSupabaseScan({ projectRef: "abc123", managementApiToken: "t", fetchImpl });
      expect(findings.some((f) => f.taxonomy.startsWith("pg_cron"))).toBe(false);
    });

    it("flags a superuser-run cron job when the cron schema is present", async () => {
      const fetchImpl = mockFetch({
        advisors: { lints: [] },
        authConfig: {},
        tables: [],
        extensions: [],
        buckets: [],
        policies: [],
        cronSchemaExists: true,
        cronJobs: [{ jobid: 1, schedule: "* * * * *", command: "select 1;", nodename: "localhost", database: "postgres", username: "postgres", active: true, isSuperuser: true }],
      });
      const findings = await runSupabaseScan({ projectRef: "abc123", managementApiToken: "t", fetchImpl });
      expect(findings.map((f) => f.taxonomy)).toContain("pg_cron job runs as a superuser role");
    });
  });

  describe("functionsDir", () => {
    let dir: string;
    afterEach(() => rmSync(dir, { recursive: true, force: true }));

    it("also runs edge-function secret/webhook checks when functionsDir is given", async () => {
      dir = mkdtempSync(join(tmpdir(), "harvey-edge-fns-"));
      mkdirSync(join(dir, "stripe-webhook"));
      writeFileSync(join(dir, "stripe-webhook", "index.ts"), `export default async (req) => { await req.json(); };`);

      const fetchImpl = mockFetch({
        advisors: { lints: [] },
        authConfig: {},
        tables: [],
        extensions: [],
        buckets: [],
        policies: [],
      });
      const findings = await runSupabaseScan({ projectRef: "abc123", managementApiToken: "t", fetchImpl, functionsDir: dir });
      expect(findings.some((f) => f.taxonomy === "Unsigned/unverified webhook handler")).toBe(true);
    });
  });

  // #54 — local mode now runs Splinter (via the injectable splinterImpl, mirroring fetchImpl
  // above) alongside the SQL-derived checks (postgres mocked via vi.mock at the top of this file).
  describe("local mode — Splinter wiring (#54)", () => {
    it("merges Splinter advisor findings with the SQL-derived checks Splinter doesn't cover", async () => {
      const splinterImpl = () => ({
        lints: [{ name: "unused_index", title: "Unused Index", level: "INFO" as const, metadata: { name: "widgets", schema: "public" }, cache_key: "unused_index_public_widgets_idx" }],
      });

      const findings = await runSupabaseScan({ local: true, splinterImpl });
      const taxonomies = findings.map((f) => f.taxonomy);

      expect(taxonomies).toContain("unused_index"); // from Splinter
      expect(taxonomies).toContain("Dangerous extension enabled"); // from checkDangerousExtensions
      expect(taxonomies).toContain("Public bucket with no policies"); // from checkPublicBucketsWithNoPolicies
      expect(findings.every((f) => f.mechanical)).toBe(true);
    });

    it("dedupes checkAutoExposedTables against Splinter's rls_disabled_in_public for the same table", async () => {
      const splinterImpl = () => ({
        lints: [{ name: "rls_disabled_in_public", title: "RLS Disabled in Public", level: "ERROR" as const, metadata: { name: "widgets", schema: "public" }, cache_key: "rls_disabled_in_public_public_widgets" }],
      });

      const findings = await runSupabaseScan({ local: true, splinterImpl });
      const rlsFindings = findings.filter((f) => f.location === "public.widgets");

      expect(rlsFindings).toHaveLength(1); // Splinter's hit only, not also "Auto-exposed public-schema table"
      expect(rlsFindings[0]?.taxonomy).toBe("rls_disabled_in_public");
    });
  });

  // #1330 (gate 4b). Local mode runs a strict subset of hosted mode's checks. The subset itself is
  // fine; returning it in silence is not — a locally-scanned project would read exactly like one
  // whose schema exposure and auth config were checked and found clean.
  describe("local mode — the omitted checks are disclosed, not silent (#1330)", () => {
    const splinterImpl = () => ({ lints: [] });

    it("emits SB-SCOPE-00 naming all three classes local mode could not read", async () => {
      const findings = await runSupabaseScan({ local: true, splinterImpl });
      const row = findings.find((f) => f.id === "SB-SCOPE-00");

      expect(row).toBeDefined();
      expect(row?.category).toBe("Coverage");
      // The three checks scanHosted runs and scanLocal does not, in the words the client reads.
      expect(row?.evidence).toContain("PostgREST-exposed schemas");
      expect(row?.evidence).toContain("GraphQL introspection");
      expect(row?.evidence).toContain("GoTrue auth configuration");
    });

    it("does not emit SB-SCOPE-00 in hosted mode, where those three checks actually run", async () => {
      const fetchImpl = mockFetch({
        advisors: { lints: [] },
        authConfig: { mailer_autoconfirm: true },
        tables: [],
        extensions: [],
        buckets: [],
        policies: [],
        postgrest: { db_schema: "public,internal" },
      });

      const findings = await runSupabaseScan({ projectRef: "abc123", managementApiToken: "t", fetchImpl });

      expect(findings.some((f) => f.id === "SB-SCOPE-00")).toBe(false);
      // The two classes the row stands in for locally are real findings here, which is why the row
      // must NOT be present: hosted mode asked the questions.
      expect(findings.some((f) => f.taxonomy === "PostgREST schema exposure wider than intended")).toBe(true);
      expect(findings.some((f) => f.taxonomy === "Auth config: email confirmation disabled")).toBe(true);
    });
  });

  // #1494 — local mode has the project's own REST URL even with no Management API credential;
  // probing PostgREST's schema allow-list answers two of SB-SCOPE-00's three omissions, narrowing
  // the disclosure to the one that genuinely needs the Management API.
  describe("local mode — a REST probe answers two of the three local-mode omissions (#1494)", () => {
    const splinterImpl = () => ({ lints: [] });

    it("emits the exposed-schema and graphql-introspection findings, and narrows SB-SCOPE-00 to just auth config", async () => {
      mockExtensions.value = [{ name: "pg_graphql", schema: "extensions", installed_version: "1.5.9" }];
      const fetchImpl = restProbeFetch("public, graphql_public, internal_ops");

      const findings = await runSupabaseScan({ local: true, splinterImpl, restUrl: "http://127.0.0.1:54321/rest/v1", fetchImpl });

      expect(findings.some((f) => f.id === "SB-API-SCHEMA-internal_ops")).toBe(true);
      expect(findings.some((f) => f.id === "SB-GRAPHQL-INTROSPECTION")).toBe(true);

      const row = findings.find((f) => f.id === "SB-SCOPE-00");
      expect(row).toBeDefined();
      expect(row?.title).toContain("1 Supabase project-config check");
      expect(row?.evidence).toContain("GoTrue auth configuration");
      // The two now-answered classes moved to real findings above, not to a narrower version of the
      // same silence — the row's own text must say so, not just its title's count.
      expect(row?.evidence).not.toContain("Three checks the hosted-mode scan runs did not run here");
    });

    it("falls back to the full 3-omission SB-SCOPE-00 when the REST probe is unreachable, even with a restUrl supplied", async () => {
      const fetchImpl = vi.fn(() => { throw new Error("ECONNREFUSED"); }) as unknown as typeof fetch;

      const findings = await runSupabaseScan({ local: true, splinterImpl, restUrl: "http://127.0.0.1:1/rest/v1", fetchImpl });

      const row = findings.find((f) => f.id === "SB-SCOPE-00");
      expect(row?.title).toContain("3 Supabase project-config checks");
      expect(row?.evidence).toContain("PostgREST-exposed schemas");
      expect(row?.evidence).toContain("GraphQL introspection");
      expect(row?.evidence).toContain("GoTrue auth configuration");
      expect(row?.evidence).toContain("ECONNREFUSED");
      expect(findings.some((f) => f.id.startsWith("SB-API-SCHEMA-"))).toBe(false);
      expect(findings.some((f) => f.id === "SB-GRAPHQL-INTROSPECTION")).toBe(false);
    });

    it("keeps the pre-#1494 3-omission SB-SCOPE-00 with no network call when no restUrl is supplied", async () => {
      const fetchImpl = vi.fn(() => { throw new Error("must not be called"); }) as unknown as typeof fetch;
      const findings = await runSupabaseScan({ local: true, splinterImpl, fetchImpl });

      expect(fetchImpl).not.toHaveBeenCalled();
      const row = findings.find((f) => f.id === "SB-SCOPE-00");
      expect(row?.title).toContain("3 Supabase project-config checks");
    });
  });

  describe("probeExposedSchemas (#1494)", () => {
    it("parses PostgREST's PGRST106 hint into the exposed-schema allow-list", async () => {
      const fetchImpl = restProbeFetch("public, graphql_public, internal_ops");
      const probe = await probeExposedSchemas("http://127.0.0.1:54321/rest/v1", fetchImpl);
      expect(probe).toEqual({ schemas: ["public", "graphql_public", "internal_ops"] });
    });

    it("reports unavailable when the REST surface cannot be reached", async () => {
      const fetchImpl = vi.fn(() => { throw new Error("ECONNREFUSED"); }) as unknown as typeof fetch;
      const probe = await probeExposedSchemas("http://127.0.0.1:1/rest/v1", fetchImpl);
      expect(probe).toEqual({ unavailable: expect.stringContaining("ECONNREFUSED") });
    });

    it("reports unavailable when the response carries no PGRST106 hint", async () => {
      const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ message: "ok" }))) as unknown as typeof fetch;
      const probe = await probeExposedSchemas("http://127.0.0.1:54321/rest/v1", fetchImpl);
      expect(probe).toEqual({ unavailable: expect.stringContaining("without a PGRST106 schema hint") });
    });
  });

  // #1264. A lint the parser could not split back into its 10 columns is missing from the advisor
  // set. It used to leave no trace at all; it now has to reach the report as a counted row.
  describe("local mode — an unparseable Splinter row is counted, not swallowed (#1264)", () => {
    it("emits SB-SPLINTER-00 naming the number of lints lost in transit", async () => {
      const findings = await runSupabaseScan({ local: true, splinterImpl: () => ({ lints: [], unparsedRows: 2 }) });
      const row = findings.find((f) => f.id === "SB-SPLINTER-00");

      expect(row).toBeDefined();
      expect(row?.category).toBe("Coverage");
      expect(row?.title).toContain("2");
      expect(row?.evidence).toContain("field separator");
    });

    // #1323. The row used to assert the never-silent invariant in full generality, which is broader
    // than the counter: `unparsedRows` only increments while fields[2] is still a Splinter level, so
    // a separator inside `name` or `title` shifts the level column and the row is dropped uncounted.
    // A disclosure row that overstates its own completeness is the defect the family exists to
    // prevent, so the bound has to be IN the row, not only in the parser's comments.
    it("states the shape that evades its own counter, rather than claiming a proven total", async () => {
      const findings = await runSupabaseScan({ local: true, splinterImpl: () => ({ lints: [], unparsedRows: 2 }) });
      const row = findings.find((f) => f.id === "SB-SPLINTER-00");

      expect(row?.evidence).toContain("third field is still a Splinter level");
      expect(row?.evidence).toContain("`name` or `title`");
      expect(row?.evidence).toContain("WITHOUT reaching this count");
      expect(row?.impact).toContain("FLOOR");
    });

    it("stays silent when every row parsed, so the row means something when it appears", async () => {
      const findings = await runSupabaseScan({ local: true, splinterImpl: () => ({ lints: [], unparsedRows: 0 }) });
      expect(findings.some((f) => f.id === "SB-SPLINTER-00")).toBe(false);
    });

    // Accounted-for is not delivered (#1433/#1435). SB-SPLINTER-00 is a confidence:"N/A" row, and
    // the whole disclosure family once reached the client PDF with its reason replaced by a stock
    // sentence. So follow this one to the rendered report rather than to a passing producer.
    it("reaches the rendered report carrying its own count and reason", async () => {
      const findings = await runSupabaseScan({ local: true, splinterImpl: () => ({ lints: [], unparsedRows: 3 }) });
      const doc = { meta: RENDER_META, findings } as FindingsDocument;
      const html = buildHtml(doc);

      expect(renderFidelityBreaches(doc, html)).toEqual([]);
      expect(html).toContain(esc("3 Supabase Advisor lint row(s) this scan could not parse"));
      expect(html).toContain(esc("could not be split back into their ten columns"));
    });
  });
});

describe("dedupeAutoExposed", () => {
  const splinterHit = mechanicalFinding({
    id: "SB-ADV-1", title: "RLS Disabled in Public", severity: "Critical", category: "Supabase advisor",
    taxonomy: "rls_disabled_in_public", location: "public.orders", evidence: "e", impact: "i", fix: "f", precisionTier: "high",
  });
  const autoExposedHit = mechanicalFinding({
    id: "SB-EXPOSED-public-orders", title: "public.orders has RLS disabled", severity: "Critical", category: "Supabase config",
    taxonomy: "Auto-exposed public-schema table", location: "public.orders", evidence: "e", impact: "i", fix: "f", precisionTier: "high",
  });
  const autoExposedOther = mechanicalFinding({
    id: "SB-EXPOSED-public-widgets", title: "public.widgets has RLS disabled", severity: "Critical", category: "Supabase config",
    taxonomy: "Auto-exposed public-schema table", location: "public.widgets", evidence: "e", impact: "i", fix: "f", precisionTier: "high",
  });

  it("drops an auto-exposed finding whose location Splinter already flagged as rls_disabled_in_public", () => {
    expect(dedupeAutoExposed([splinterHit], [autoExposedHit])).toEqual([]);
  });

  it("keeps an auto-exposed finding for a table Splinter didn't flag", () => {
    expect(dedupeAutoExposed([splinterHit], [autoExposedOther])).toEqual([autoExposedOther]);
  });

  it("keeps auto-exposed findings untouched when Splinter found nothing", () => {
    expect(dedupeAutoExposed([], [autoExposedHit, autoExposedOther])).toEqual([autoExposedHit, autoExposedOther]);
  });
});

describe("hasPgGraphql (FP-safe pg_graphql derivation)", () => {
  it("is false when pg_graphql is not among the installed extensions (the ATC case)", () => {
    // pg_extension lists installed extensions only — pg_graphql absent = not enabled.
    expect(hasPgGraphql([{ name: "pgcrypto", schema: "extensions", installed_version: "1.3" }])).toBe(false);
    expect(hasPgGraphql([])).toBe(false);
  });

  it("is false when pg_graphql is listed but has no installed_version", () => {
    // available-but-not-installed must NOT count as enabled.
    expect(hasPgGraphql([{ name: "pg_graphql", schema: "graphql", installed_version: null as unknown as string }])).toBe(false);
    expect(hasPgGraphql([{ name: "pg_graphql", schema: "graphql", installed_version: "" }])).toBe(false);
  });

  it("is true only when pg_graphql is installed with a version", () => {
    expect(hasPgGraphql([{ name: "pg_graphql", schema: "graphql", installed_version: "1.5.9" }])).toBe(true);
  });

  it("end-to-end: the ATC scenario (graphql_public exposed but pg_graphql off) is CLEAN", () => {
    // This is the exact false positive from the 2026-07-11 live run: graphql_public is in the
    // exposed schema list, but pg_graphql isn't installed, so introspection must NOT be flagged.
    const exposed = parseExposedSchemas({ db_schema: "public, graphql_public" });
    const installed = hasPgGraphql([{ name: "pgcrypto", schema: "extensions", installed_version: "1.3" }]);
    expect(exposed).toEqual(["public", "graphql_public"]);
    expect(installed).toBe(false);
    expect(checkGraphqlIntrospection(installed, exposed)).toEqual([]);
  });

  it("still fires when pg_graphql IS installed and graphql_public is exposed", () => {
    const exposed = parseExposedSchemas({ db_schema: "public, graphql_public" });
    const installed = hasPgGraphql([{ name: "pg_graphql", schema: "graphql", installed_version: "1.5.9" }]);
    expect(checkGraphqlIntrospection(installed, exposed)).toHaveLength(1);
  });
});

describe("parseExposedSchemas", () => {
  it("splits, trims, and drops empties from the PostgREST db_schema config", () => {
    expect(parseExposedSchemas({ db_schema: "public,  graphql_public , internal " })).toEqual(["public", "graphql_public", "internal"]);
    expect(parseExposedSchemas({ db_schema: "" })).toEqual([]);
    expect(parseExposedSchemas({})).toEqual([]);
  });
});

// #1265 — the Management API SQL envelope, assumed since this module was written and never
// checked. These read the CAPTURED vendor spec
// (src/scan/__fixtures__/supabase/database-query-schema-2026-07-31.json), so what they guard is the
// agreement between Harvey's request and Supabase's published contract: re-capture the fixture and
// a contract change fails here instead of at the first hosted run against a client's project.
describe("Management API /database/query envelope (#1265, against the captured vendor spec)", () => {
  const spec = JSON.parse(
    readFileSync(new URL("./__fixtures__/supabase/database-query-schema-2026-07-31.json", import.meta.url), "utf8"),
  ) as {
    paths: Record<string, { post?: { responses: Record<string, unknown>; "x-oauth-scope"?: string } }>;
    components: { schemas: Record<string, { properties: Record<string, unknown>; required: string[] }> };
  };

  async function capturedRequestBody(): Promise<{ body: Record<string, unknown>; status: number }> {
    let body: Record<string, unknown> = {};
    let status = 0;
    const fetchImpl = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const u = url.toString();
      if (u.includes("/database/query")) {
        body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
        // The documented success code, not 200 — a scan that only accepted 200 would break on
        // every hosted project while passing every test that mocked 200.
        status = 201;
        return new Response(JSON.stringify([]), { status: 201 });
      }
      if (u.includes("/advisors/security")) return new Response(JSON.stringify({ lints: [] }));
      if (u.includes("/config/auth")) return new Response(JSON.stringify({}));
      if (u.includes("/postgrest")) return new Response(JSON.stringify({ db_schema: "public" }));
      return new Response("not found", { status: 404 });
    }) as unknown as typeof fetch;
    await runSupabaseScan({ projectRef: "abcdefghijklmnopqrst", managementApiToken: "t", fetchImpl });
    return { body, status };
  }

  it("sends every key the spec requires, and nothing the spec does not declare", async () => {
    const { body } = await capturedRequestBody();
    const schema = spec.components.schemas.V1RunQueryBody!;
    expect(schema.required).toEqual(["query"]);
    for (const key of schema.required) expect(Object.keys(body)).toContain(key);
    for (const key of Object.keys(body)) expect(Object.keys(schema.properties)).toContain(key);
  });

  it("opts into read_only on every SQL call — the endpoint's own scope is database:write", async () => {
    const { body } = await capturedRequestBody();
    expect(body.read_only, "a read-only pass must not reach a write-scoped endpoint without it").toBe(true);
    expect(spec.paths["/v1/projects/{ref}/database/query"]?.post?.["x-oauth-scope"]).toBe("database:write");
  });

  it("accepts the documented 201, which is not 200", async () => {
    const { status } = await capturedRequestBody();
    expect(status).toBe(201);
    expect(Object.keys(spec.paths["/v1/projects/{ref}/database/query"]?.post?.responses ?? {})).toContain("201");
  });

  // The half the spec does NOT settle, pinned so the gap stays visible: the 201 carries no content
  // schema, which is why the bare-row-array shape is evidenced from the vendor's own client instead
  // (see this module's header) and why PROVENANCE.md still carries a reason for the live capture.
  it("records that the spec documents no response schema for the 201", () => {
    expect(spec.paths["/v1/projects/{ref}/database/query"]?.post?.responses["201"]).toEqual({ description: "" });
  });

  it("pins db_schema as a REQUIRED string on the PostgREST config response", () => {
    const schema = spec.components.schemas.PostgrestConfigWithJWTSecretResponse!;
    expect(schema.required).toContain("db_schema");
    expect(schema.properties.db_schema).toEqual({ type: "string" });
  });
});
