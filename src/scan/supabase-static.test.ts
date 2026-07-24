import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  checkEdgeFunctionVerifyJwt,
  checkMigrationDefinerAuthz,
  checkMigrationPolicySemantics,
  checkMigrationRlsInitplanStatic,
  checkMigrationRlsStatic,
  checkOpenSignupConfig,
  inferAuthMethodsFromSource,
  type TenancyOverride,
} from "./supabase-static.js";

describe("checkMigrationRlsStatic", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function writeMigrations(files: Record<string, string>): string {
    root = mkdtempSync(join(tmpdir(), "harvey-rls-"));
    const dir = join(root, "supabase", "migrations");
    mkdirSync(dir, { recursive: true });
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return root;
  }

  it("flags a public table that never gets ENABLE RLS", () => {
    const dir = writeMigrations({
      "0001_schema.sql": "create table public.audit_logs (id uuid primary key);",
    });
    const findings = checkMigrationRlsStatic(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain("public.audit_logs");
    expect(findings[0]!.precisionTier).toBe("high");
  });

  it("clears a table whose RLS is enabled in a LATER migration file", () => {
    const dir = writeMigrations({
      "0001_schema.sql": "create table public.documents (id uuid primary key);",
      "0002_rls.sql": "alter table public.documents enable row level security;",
    });
    expect(checkMigrationRlsStatic(dir)).toEqual([]);
  });

  it("clears a service-only deny-all table (RLS enabled, zero policies)", () => {
    const dir = writeMigrations({
      "0001_schema.sql": "create table public.service_state (id uuid primary key);",
      "0002_rls.sql": "alter table public.service_state enable row level security;",
    });
    expect(checkMigrationRlsStatic(dir)).toEqual([]);
  });

  it("ignores views (no RLS concept) and if-not-exists / only variants", () => {
    const dir = writeMigrations({
      "0001.sql": [
        "create view public.user_directory as select id from auth.users;",
        "create table if not exists public.reports (id uuid primary key);",
        "alter table only public.reports enable row level security;",
      ].join("\n"),
    });
    expect(checkMigrationRlsStatic(dir)).toEqual([]);
  });

  it("does not treat commented-out DDL as a real enable statement", () => {
    const dir = writeMigrations({
      "0001_schema.sql": "create table public.audit_logs (id uuid primary key);",
      "0002_rls.sql": '-- (Intentionally NO "alter table public.audit_logs enable row level security;")',
    });
    expect(checkMigrationRlsStatic(dir)).toHaveLength(1);
  });

  it("flags only the uncovered table when a migration set mixes both", () => {
    const dir = writeMigrations({
      "0001_schema.sql": [
        "create table public.notes (id uuid primary key);",
        "create table public.audit_logs (id uuid primary key);",
      ].join("\n"),
      "0002_rls.sql": "alter table public.notes enable row level security;",
    });
    const names = checkMigrationRlsStatic(dir).map((f) => f.title);
    expect(names).toHaveLength(1);
    expect(names[0]).toContain("audit_logs");
  });

  // #565 — a no-code export commits its schema as a root schema.sql, not supabase/migrations/*.sql.
  it("flags an RLS-off table read from a root schema.sql (no supabase/migrations)", () => {
    root = mkdtempSync(join(tmpdir(), "harvey-rls-"));
    writeFileSync(join(root, "schema.sql"), "create table public.nocode_tickets (id uuid primary key);");
    const findings = checkMigrationRlsStatic(root);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain("public.nocode_tickets");
    expect(findings[0]!.location).toContain("schema.sql");
    expect(findings[0]!.precisionTier).toBe("high");
  });

  it("clears a root schema.sql table that enables RLS", () => {
    root = mkdtempSync(join(tmpdir(), "harvey-rls-"));
    writeFileSync(
      join(root, "schema.sql"),
      "create table public.nocode_safe (id uuid primary key);\nalter table public.nocode_safe enable row level security;",
    );
    expect(checkMigrationRlsStatic(root)).toEqual([]);
  });

  it("aggregates enables across supabase/migrations AND a root schema.sql", () => {
    const dir = writeMigrations({ "0002_rls.sql": "alter table public.nocode_tickets enable row level security;" });
    writeFileSync(join(dir, "schema.sql"), "create table public.nocode_tickets (id uuid primary key);");
    expect(checkMigrationRlsStatic(dir)).toEqual([]);
  });
});

describe("checkEdgeFunctionVerifyJwt", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function writeConfig(toml: string): string {
    root = mkdtempSync(join(tmpdir(), "harvey-verifyjwt-"));
    mkdirSync(join(root, "supabase"), { recursive: true });
    writeFileSync(join(root, "supabase", "config.toml"), toml);
    return root;
  }

  it("flags a [functions.X] section with verify_jwt = false", () => {
    const dir = writeConfig("[functions.admin-refund]\nverify_jwt = false\n");
    const findings = checkEdgeFunctionVerifyJwt(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain("admin-refund");
    expect(findings[0]!.precisionTier).toBe("review");
  });

  it("clears verify_jwt = true and a bare verify_jwt = false outside any [functions.X] table", () => {
    const dir = writeConfig("[functions.user-profile]\nverify_jwt = true\n\n[auth]\nverify_jwt = false\n");
    expect(checkEdgeFunctionVerifyJwt(dir)).toEqual([]);
  });
});

describe("checkOpenSignupConfig (#588)", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function writeConfig(toml: string): string {
    root = mkdtempSync(join(tmpdir(), "harvey-signup-"));
    mkdirSync(join(root, "supabase"), { recursive: true });
    writeFileSync(join(root, "supabase", "config.toml"), toml);
    return root;
  }

  it("flags [auth] enable_signup = true and [auth.email] enable_confirmations = false", () => {
    const dir = writeConfig("[auth]\nenable_signup = true\n\n[auth.email]\nenable_confirmations = false\n");
    const findings = checkOpenSignupConfig(dir);
    expect(findings.map((f) => f.id).sort()).toEqual(["SB-EMAIL-CONFIRM-OFF", "SB-OPEN-SIGNUP"]);
    expect(findings.every((f) => f.precisionTier === "review")).toBe(true);
  });

  it("clears the safe values (enable_signup = false, enable_confirmations = true)", () => {
    const dir = writeConfig("[auth]\nenable_signup = false\n\n[auth.email]\nenable_confirmations = true\n");
    expect(checkOpenSignupConfig(dir)).toEqual([]);
  });

  it("scopes by section — the [auth.sms] siblings are not flagged", () => {
    const dir = writeConfig("[auth]\nenable_signup = false\n\n[auth.sms]\nenable_signup = true\nenable_confirmations = false\n");
    expect(checkOpenSignupConfig(dir)).toEqual([]);
  });

  // #671 — the email-confirmation advisor is conditional on email auth actually being used.
  it("keeps SB-EMAIL-CONFIRM-OFF a Medium when email auth is in use", () => {
    const dir = writeConfig("[auth.email]\nenable_confirmations = false\n");
    const f = checkOpenSignupConfig(dir, { email: true, phone: false }).find((x) => x.id === "SB-EMAIL-CONFIRM-OFF")!;
    expect(f.severity).toBe("Medium");
    expect(f.title).not.toContain("conditional");
  });

  it("reframes SB-EMAIL-CONFIRM-OFF to an Info conditional on an OAuth-only app (email off)", () => {
    const dir = writeConfig("[auth.email]\nenable_confirmations = false\n");
    const f = checkOpenSignupConfig(dir, { email: false, phone: false }).find((x) => x.id === "SB-EMAIL-CONFIRM-OFF")!;
    expect(f.severity).toBe("Info");
    expect(f.title).toContain("conditional");
  });
});

describe("inferAuthMethodsFromSource (#671)", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function writeRepo(files: Record<string, string>): string {
    root = mkdtempSync(join(tmpdir(), "harvey-authinfer-"));
    for (const [rel, content] of Object.entries(files)) {
      const full = join(root, rel);
      mkdirSync(join(full, ".."), { recursive: true });
      writeFileSync(full, content);
    }
    return root;
  }

  it("infers email auth in use from a signInWithPassword call", () => {
    const dir = writeRepo({ "src/login.ts": "await supabase.auth.signInWithPassword({ email, password });" });
    expect(inferAuthMethodsFromSource(dir)).toEqual({ email: true, phone: false });
  });

  it("infers email OFF (conditional) for an OAuth-only app", () => {
    const dir = writeRepo({ "src/login.ts": "await supabase.auth.signInWithOAuth({ provider: 'google' });" });
    expect(inferAuthMethodsFromSource(dir)).toEqual({ email: false, phone: false });
  });

  it("infers phone OTP in use and email off when only phone OTP is called", () => {
    const dir = writeRepo({ "src/login.ts": "await supabase.auth.signInWithOtp({ phone: '+15551234567' });" });
    expect(inferAuthMethodsFromSource(dir)).toEqual({ email: false, phone: true });
  });

  it("returns undefined for both when there is no auth evidence at all", () => {
    const dir = writeRepo({ "src/util.ts": "export const noop = () => {};" });
    expect(inferAuthMethodsFromSource(dir)).toEqual({ email: undefined, phone: undefined });
  });

  it("reads email/OAuth enablement from supabase/config.toml provider toggles", () => {
    const dir = writeRepo({
      "supabase/config.toml": "[auth.email]\nenable_signup = true\n\n[auth.external.github]\nenabled = true\n",
    });
    expect(inferAuthMethodsFromSource(dir)).toEqual({ email: true, phone: false });
  });
});

// #220 — the source-tier semantic policy review. Fixtures are modelled on the two REAL Criticals
// from the 2026-07-12 public sweep (both plain `create policy` text in committed migrations) and
// their benign lookalikes, per the #61 positive/negative-pair discipline.
describe("checkMigrationPolicySemantics", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function writeMigrations(files: Record<string, string>): string {
    root = mkdtempSync(join(tmpdir(), "harvey-policy-"));
    const dir = join(root, "supabase", "migrations");
    mkdirSync(dir, { recursive: true });
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return root;
  }

  const schema = "create table public.memberships (id uuid primary key, tenant_id uuid not null, user_id uuid not null);";

  // The policy verdicts, without the SB-RLS-TENANCY-MODEL assumption record (#258) that every run
  // with policies emits. These tests are about which policies get FLAGGED; the assumption record is
  // covered on its own below.
  const reviews = (dir: string) => checkMigrationPolicySemantics(dir).filter((f) => f.id !== "SB-RLS-TENANCY-MODEL");

  it("flags an INSERT policy that checks the caller but never the tenant column (the self-join Critical)", () => {
    // supabase-multi-tenant-starter …_rls_policies.sql:92-97 — WITH CHECK keys on auth.uid()
    // alone, so a member can insert a membership row into any tenant.
    const dir = writeMigrations({
      "0001.sql": schema,
      "0002.sql": "create policy memberships_insert on public.memberships for insert with check (user_id = auth.uid());",
    });
    const findings = reviews(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain("tenant key");
    expect(findings[0]!.category).toBe("Multi-tenant security");
  });

  it("flags an UPDATE policy whose WITH CHECK drops the tenant constraint (the unscoped-invite Critical)", () => {
    const dir = writeMigrations({
      "0001.sql": schema,
      "0002.sql": "create policy m_update on public.memberships for update using (tenant_id = current_tenant()) with check (true);",
    });
    expect(reviews(dir)[0]!.evidence).toContain("WITH CHECK");
  });

  it("clears a correctly tenant-scoped policy — the benign lookalike", () => {
    const dir = writeMigrations({
      "0001.sql": schema,
      "0002.sql": "create policy m_all on public.memberships for all using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid) with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);",
    });
    expect(reviews(dir)).toEqual([]);
  });

  it("locates the finding at its migration file:line — the address a source-tier reader can act on", () => {
    const dir = writeMigrations({
      "0001.sql": schema,
      "0002.sql": "-- header\ncreate policy m_insert on public.memberships for insert with check (user_id = auth.uid());",
    });
    expect(reviews(dir)[0]!.location).toContain("supabase/migrations/0002.sql:2");
  });

  it("stays at review tier — static shape is an indicator, never a graded verdict (#227)", () => {
    const dir = writeMigrations({
      "0001.sql": schema,
      "0002.sql": "create policy m_insert on public.memberships for insert with check (user_id = auth.uid());",
    });
    expect(checkMigrationPolicySemantics(dir).every((f) => f.precisionTier === "review")).toBe(true);
  });

  it("reviews a per-user app in per-user mode rather than inventing a tenant key (the #206 FP)", () => {
    // No tenant column in the schema: id = auth.uid() is correct owner isolation here, and must
    // not be flagged for failing to reference a tenant key the app doesn't have.
    const dir = writeMigrations({
      "0001.sql": "create table public.profiles (id uuid primary key, email text);",
      "0002.sql": "create policy p_select on public.profiles for select using (id = auth.uid());",
    });
    expect(reviews(dir)).toEqual([]);
  });

  it("surfaces the own-row-with-tenant_id shape at REVIEW tier, not the free count (#257)", () => {
    // profiles is owner-scoped by its identity (id = auth.uid()) yet declares tenant_id for joins,
    // so it reviews per-tenant and the caller-identity rule fires. That FP is NOT statically
    // separable from a tenant table wrongly keyed on the user (the #206 bug the rule must keep
    // catching), so the honest resolution is to keep it at review tier — surfaced and triaged out,
    // never a graded/free-count finding — rather than narrow the rule and break the #206 tests.
    const dir = writeMigrations({
      "0001.sql": "create table public.profiles (id uuid primary key, tenant_id uuid not null, email text);",
      "0002.sql": "create policy profiles_select_self on public.profiles for select using (id = auth.uid());",
    });
    const flagged = reviews(dir).filter((f) => f.location.includes("profiles_select_self"));
    expect(flagged).toHaveLength(1);
    expect(flagged[0]!.precisionTier).toBe("review");
    expect(flagged[0]!.precisionTier).not.toBe("high");
  });

  it("reports a policy it could not parse rather than passing over it in silence", () => {
    const dir = writeMigrations({
      "0001.sql": schema,
      "0002.sql": "create policy m_broken on public.memberships for select using (tenant_id = current_tenant()",
    });
    const findings = reviews(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toContain("could not be read");
    expect(findings[0]!.evidence).toContain("not assessed");
  });

  it("returns nothing for a target with no migrations at all", () => {
    root = mkdtempSync(join(tmpdir(), "harvey-policy-"));
    expect(checkMigrationPolicySemantics(root)).toEqual([]);
  });

  // #937 — a broken policy a later migration DROPs and replaces must not be reported against the
  // final schema. Before this, migrations were read cumulatively, so a fixed schema produced output
  // byte-identical to the broken one it replaced.
  describe("drop/replace lifecycle (#937)", () => {
    const leak = "create policy documents_read on public.memberships for select using (true);";

    it("flags a leaky USING(true) policy while it is still live (the broken variant)", () => {
      const dir = writeMigrations({ "0001.sql": schema, "0002.sql": leak });
      expect(reviews(dir)).toHaveLength(1);
    });

    it("does NOT flag the leak once a later migration DROPs and replaces it (the fixed variant)", () => {
      const dir = writeMigrations({
        "0001.sql": schema,
        "0002.sql": leak,
        "0003_fix.sql": [
          "drop policy documents_read on public.memberships;",
          "create policy documents_read on public.memberships for select using (tenant_id = current_tenant());",
        ].join("\n"),
      });
      expect(reviews(dir)).toEqual([]);
    });

    it("does NOT flag the leak when a later migration simply DROPs it", () => {
      const dir = writeMigrations({
        "0001.sql": schema,
        "0002.sql": leak,
        "0003_drop.sql": "drop policy documents_read on public.memberships;",
      });
      expect(reviews(dir)).toEqual([]);
    });
  });
});

// #258 — the tenant-key inference is a fixed 6-name list. An app using another convention reviews
// every table in per-user mode, so cross-tenant findings are missed AND the miss is invisible:
// silence from a failed inference reads exactly like a clean result. The assumption must be stated.
describe("checkMigrationPolicySemantics — tenancy-model disclosure (#258)", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function writeMigrations(sql: string): string {
    root = mkdtempSync(join(tmpdir(), "harvey-tenancy-"));
    const dir = join(root, "supabase", "migrations");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "0001.sql"), sql);
    return root;
  }

  const model = (dir: string, override?: TenancyOverride) =>
    checkMigrationPolicySemantics(dir, override).find((f) => f.id === "SB-RLS-TENANCY-MODEL");

  it("names the tenant key it assumed for a recognised per-tenant table", () => {
    const dir = writeMigrations(
      "create table public.notes (id uuid primary key, tenant_id uuid not null);\n" +
        "create policy n_all on public.notes for all using (tenant_id = current_tenant()) with check (tenant_id = current_tenant());",
    );
    expect(model(dir)!.evidence).toContain('notes → per-tenant on "tenant_id"');
  });

  it("says a table was reviewed as per-user AND names the unrecognised scoping column (the site_id app)", () => {
    // The exact #258 failure: `site_id` is off the candidate list, so pages reviews per-user and
    // any cross-tenant bug in it is never looked for. Previously that was silent.
    const dir = writeMigrations(
      "create table public.pages (id uuid primary key, site_id uuid not null);\n" +
        "create policy p_all on public.pages for all using (site_id = current_site()) with check (site_id = current_site());",
    );
    const evidence = model(dir)!.evidence;
    expect(evidence).toContain("NOT RECOGNISED");
    expect(evidence).toContain("pages (declares site_id)");
    expect(evidence).toContain("WAS NOT LOOKED FOR");
  });

  it("does not cry wolf over an owner column or a plain per-user table", () => {
    // profiles keyed id = auth.uid() is per-user BY DESIGN, not a failed inference. Reporting it as
    // an unrecognised tenant key would bury the one table that matters.
    const dir = writeMigrations(
      "create table public.profiles (id uuid primary key, user_id uuid not null, email text);\n" +
        "create policy p_sel on public.profiles for select using (id = auth.uid());",
    );
    expect(model(dir)!.evidence).not.toContain("NOT RECOGNISED");
  });

  it("is Info-tier and never counted as a defect — an assumption made visible is not a finding", () => {
    const dir = writeMigrations(
      "create table public.pages (id uuid primary key, site_id uuid not null);\n" +
        "create policy p_all on public.pages for all using (site_id = current_site()) with check (site_id = current_site());",
    );
    const f = model(dir)!;
    expect(f.severity).toBe("Info");
    expect(f.precisionTier).toBe("review");
  });

  it("is not emitted for a migration set that declares no policies at all", () => {
    expect(model(writeMigrations("create table public.notes (id uuid primary key);"))).toBeUndefined();
  });

  it("states the two recognised signals so an empty list isn't proof of a clean result (#281)", () => {
    const dir = writeMigrations(
      "create table public.notes (id uuid primary key, tenant_id uuid not null);\n" +
        "create policy n_all on public.notes for all using (tenant_id = current_tenant()) with check (tenant_id = current_tenant());",
    );
    const evidence = model(dir)!.evidence;
    expect(evidence).toContain('names a column when it ends in "_id" OR is a foreign key to a tenant-shaped table');
    expect(evidence).toContain("is not proof");
  });

  // #301 — a bare (non-_id) scoping column with a novel name is invisible to the _id scan, but a
  // FOREIGN KEY to a tenant-shaped table is structural evidence it is the tenant key under an
  // off-list name. That FK, not the name, is what lets us surface it without flooding.
  it("names a bare non-_id column that foreign-keys to a tenant-shaped table (#301)", () => {
    const dir = writeMigrations(
      "create table public.widgets (id uuid primary key, site uuid not null references public.tenants(id), label text);\n" +
        "create policy w_sel on public.widgets for select using (site = current_tenant());",
    );
    const evidence = model(dir)!.evidence;
    expect(evidence).toContain("NOT RECOGNISED");
    expect(evidence).toContain("widgets (declares site)");
  });

  it("also recognises a table-level foreign-key constraint to a tenant table (#301)", () => {
    const dir = writeMigrations(
      "create table public.widgets (id uuid primary key, site uuid not null, label text, foreign key (site) references public.organizations(id));\n" +
        "create policy w_sel on public.widgets for select using (site = current_tenant());",
    );
    expect(model(dir)!.evidence).toContain("widgets (declares site)");
  });

  // The precision boundary: a bare column of the SAME shape whose FK targets a NON-tenant table is
  // an ordinary relation. Naming it is the false-positive flood that kept #301 open — it must not.
  it("does NOT name a bare column whose foreign key targets a non-tenant table (#301 non-flood)", () => {
    const dir = writeMigrations(
      "create table public.gadgets (id uuid primary key, city uuid not null references public.cities(id), status text);\n" +
        "create policy g_sel on public.gadgets for select using (id = auth.uid());",
    );
    expect(model(dir)!.evidence).not.toContain("NOT RECOGNISED");
  });

  // #280 — the static tier used to be able to SEE an off-list convention (via NOT RECOGNISED)
  // but never CORRECT it; --tenant-key/--tenant-mode let the operator declare it, the same shape
  // detect-deeper.ts already accepts at the connected tier.
  describe("--tenant-key / --tenant-mode override (#280)", () => {
    it("reviews a table declaring the overridden column as per-tenant on it", () => {
      const dir = writeMigrations(
        "create table public.pages (id uuid primary key, site_id uuid not null);\n" +
          "create policy p_all on public.pages for all using (site_id = current_site()) with check (site_id = current_site());",
      );
      const evidence = model(dir, { tenantKey: "site_id" })!.evidence;
      expect(evidence).toContain('pages → per-tenant on "site_id"');
      expect(evidence).not.toContain("NOT RECOGNISED");
    });

    it("leaves a table that does NOT declare the overridden column reviewed as per-user, unaffected", () => {
      const dir = writeMigrations(
        "create table public.pages (id uuid primary key, site_id uuid not null);\n" +
          "create policy p_all on public.pages for all using (site_id = current_site()) with check (site_id = current_site());\n" +
          "create table public.profiles (id uuid primary key, user_id uuid not null);\n" +
          "create policy pr_sel on public.profiles for select using (id = auth.uid());",
      );
      const evidence = model(dir, { tenantKey: "site_id" })!.evidence;
      expect(evidence).toContain("profiles");
      expect(evidence).toMatch(/per-user.*profiles/);
    });

    it("still finds the built-in candidates when the override key isn't the one a table declares", () => {
      const dir = writeMigrations(
        "create table public.notes (id uuid primary key, tenant_id uuid not null);\n" +
          "create policy n_all on public.notes for all using (tenant_id = current_tenant()) with check (tenant_id = current_tenant());",
      );
      expect(model(dir, { tenantKey: "site_id" })!.evidence).toContain('notes → per-tenant on "tenant_id"');
    });

    it("--tenant-mode per-user forces every table to per-user, overriding a recognised tenant column", () => {
      const dir = writeMigrations(
        "create table public.notes (id uuid primary key, tenant_id uuid not null);\n" +
          "create policy n_all on public.notes for all using (tenant_id = current_tenant()) with check (tenant_id = current_tenant());",
      );
      const evidence = model(dir, { mode: "per-user" })!.evidence;
      expect(evidence).toContain("(none — no table declared a recognised tenant column)");
      expect(evidence).toMatch(/per-user.*notes/);
    });

    it("no longer reads as upgrade-to-fix — the fix text points at this same tier's flag", () => {
      const dir = writeMigrations(
        "create table public.pages (id uuid primary key, site_id uuid not null);\n" +
          "create policy p_all on public.pages for all using (site_id = current_site()) with check (site_id = current_site());",
      );
      expect(model(dir)!.fix).toContain("--tenant-key");
      expect(model(dir)!.fix).toContain("quick-scan");
    });
  });
});

// #338 — usingTrueReview spares `USING (true)` on a table with no recognised tenant key (the
// public-catalog case), but a spared policy is silent exactly like a correct one. This disclosure
// names the spared tables so a reader can falsify the sparing rather than infer safety from silence.
describe("checkMigrationPolicySemantics — USING(true) unassessed disclosure (#338)", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function writeMigrations(sql: string): string {
    root = mkdtempSync(join(tmpdir(), "harvey-usingtrue-"));
    const dir = join(root, "supabase", "migrations");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "0001.sql"), sql);
    return root;
  }

  const disclosure = (dir: string, override?: TenancyOverride) =>
    checkMigrationPolicySemantics(dir, override).find((f) => f.id === "SB-RLS-USING-TRUE-UNASSESSED");

  it("names a table whose USING(true) was spared for want of a tenant key (the catalog shape)", () => {
    const dir = writeMigrations(
      "create table public.plans (id uuid primary key, name text);\n" +
        "create policy plans_select_public on public.plans for select using (true);",
    );
    expect(disclosure(dir)!.evidence).toContain("plans (plans_select_public)");
  });

  it("is Info-tier and non-grading — an assumption disclosure, not a finding", () => {
    const dir = writeMigrations(
      "create table public.plans (id uuid primary key, name text);\n" +
        "create policy plans_select_public on public.plans for select using (true);",
    );
    const f = disclosure(dir)!;
    expect(f.severity).toBe("Info");
    expect(f.precisionTier).toBe("review");
  });

  it("does not fire when the USING(true) table declares a tenant key — that shape is assessed and flagged, not spared", () => {
    const dir = writeMigrations(
      "create table public.documents (id uuid primary key, tenant_id uuid not null);\n" +
        "create policy d_all on public.documents for select using (true);",
    );
    expect(disclosure(dir)).toBeUndefined();
  });

  it("does not fire when the operator DECLARED per-user globally — a declaration is not an unassessed silence", () => {
    const dir = writeMigrations(
      "create table public.plans (id uuid primary key, name text);\n" +
        "create policy plans_select_public on public.plans for select using (true);",
    );
    expect(disclosure(dir, { mode: "per-user" })).toBeUndefined();
  });

  it("does not fire when no per-user table carries a USING(true) policy", () => {
    const dir = writeMigrations(
      "create table public.profiles (id uuid primary key, email text);\n" +
        "create policy p_sel on public.profiles for select using (id = auth.uid());",
    );
    expect(disclosure(dir)).toBeUndefined();
  });
});

// #264 — the static feed for definer-review.ts, whose own unit tests already cover the reviewer's
// judgment. What's tested here is what only this layer can get wrong: reaching the function bodies
// in committed SQL, and staying silent on the shapes that are not client-reachable escalations.
describe("checkMigrationDefinerAuthz", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function writeMigrations(files: Record<string, string>): string {
    root = mkdtempSync(join(tmpdir(), "harvey-definer-"));
    const dir = join(root, "supabase", "migrations");
    mkdirSync(dir, { recursive: true });
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return root;
  }

  const promoteToAdmin = `
create or replace function public.promote_to_admin(target_user_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  update public.profiles set role = 'admin' where id = target_user_id;
end;
$$;
grant execute on function public.promote_to_admin(uuid) to authenticated;`;

  it("flags a SECURITY DEFINER privileged write with no caller check (P-SECDEF-PRIV-WRITE-NOAUTH)", () => {
    const dir = writeMigrations({ "0001_secdef.sql": promoteToAdmin });
    const findings = checkMigrationDefinerAuthz(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.id).toBe("SB-DEFINER-AUTHZ-public.promote_to_admin(target_user_id)");
    // Never free-count: the body-read can't see a wrapper's own gate, so this is triage-tier.
    expect(findings[0]!.precisionTier).toBe("review");
    expect(findings[0]!.location).toContain("0001_secdef.sql:2 (public.promote_to_admin(target_user_id))");
  });

  // --- Near-miss negatives: the FP shapes this rule must stay silent on ---

  it("clears the same write when the body checks the CALLER's own role first", () => {
    const dir = writeMigrations({
      "0001_secdef.sql": `
create or replace function public.promote_to_admin_checked(target_user_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.profiles where id = auth.uid() and role = 'admin') then
    raise exception 'not authorized';
  end if;
  update public.profiles set role = 'admin' where id = target_user_id;
end;
$$;`,
    });
    expect(checkMigrationDefinerAuthz(dir)).toEqual([]);
  });

  it("clears a SECURITY DEFINER function that only READS — no privileged write to escalate with", () => {
    const dir = writeMigrations({
      "0001_secdef.sql": `
create or replace function public.get_invoice_total(invoice uuid)
returns numeric language sql security definer set search_path = public as $$
  select sum(amount) from public.invoice_lines where invoice_id = invoice;
$$;`,
    });
    expect(checkMigrationDefinerAuthz(dir)).toEqual([]);
  });

  it("clears an unchecked write whose EXECUTE is revoked from the client roles", () => {
    const dir = writeMigrations({
      "0001_secdef.sql": `
create or replace function public.promote_admin(target uuid)
returns void language sql security definer set search_path = public as $$
  update public.profiles set role = 'admin' where id = target;
$$;
revoke execute on function public.promote_admin(uuid) from public;`,
    });
    expect(checkMigrationDefinerAuthz(dir)).toEqual([]);
  });

  it("still flags when EXECUTE is revoked from some OTHER role — the client can reach it", () => {
    const dir = writeMigrations({
      "0001_secdef.sql": `${promoteToAdmin}
revoke execute on function public.promote_to_admin(uuid) from reporting_readonly;`,
    });
    expect(checkMigrationDefinerAuthz(dir)).toHaveLength(1);
  });

  it("ignores a function that is not SECURITY DEFINER (it runs as the caller already)", () => {
    const dir = writeMigrations({
      "0001_secdef.sql": `
create or replace function public.touch_profile(target uuid)
returns void language sql as $$
  update public.profiles set updated_at = now() where id = target;
$$;`,
    });
    expect(checkMigrationDefinerAuthz(dir)).toEqual([]);
  });

  it("returns nothing when the target has no migrations at all", () => {
    root = mkdtempSync(join(tmpdir(), "harvey-definer-"));
    expect(checkMigrationDefinerAuthz(root)).toEqual([]);
  });
});

describe("checkMigrationRlsInitplanStatic (#374)", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function writeMigrations(files: Record<string, string>): string {
    root = mkdtempSync(join(tmpdir(), "harvey-initplan-"));
    const dir = join(root, "supabase", "migrations");
    mkdirSync(dir, { recursive: true });
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return root;
  }

  it("flags a bare auth.uid() in a USING clause at review tier, never the free count", () => {
    const dir = writeMigrations({
      "0001_rls.sql": `create policy orders_select_own on public.orders
  for select using (tenant_id = public.current_tenant_id() and created_by = auth.uid());`,
    });
    const findings = checkMigrationRlsInitplanStatic(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.precisionTier).toBe("review");
    expect(findings[0]!.severity).toBe("Perf");
    expect(findings[0]!.evidence).toContain("auth.uid() in USING");
    expect(findings[0]!.location).toContain("0001_rls.sql:1");
    expect(findings[0]!.location).toContain("public.orders.orders_select_own");
  });

  it("flags a bare auth.role() in a WITH CHECK clause", () => {
    const dir = writeMigrations({
      "0001_rls.sql": `create policy orders_insert on public.orders
  for insert with check (auth.role() = 'authenticated');`,
    });
    const findings = checkMigrationRlsInitplanStatic(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain("auth.role() in WITH CHECK");
  });

  it("clears a call already wrapped as (select auth.uid()) — the hoisted initplan shape", () => {
    const dir = writeMigrations({
      "0001_rls.sql": `create policy events_select_own on public.events
  for select using (tenant_id = public.current_tenant_id() and actor = (select auth.uid()));`,
    });
    expect(checkMigrationRlsInitplanStatic(dir)).toEqual([]);
  });

  it("clears the wrapper regardless of case and inner whitespace: ( SELECT auth.uid() )", () => {
    const dir = writeMigrations({
      "0001_rls.sql": `create policy events_select_own on public.events
  for select using (actor = ( SELECT auth.uid() ));`,
    });
    expect(checkMigrationRlsInitplanStatic(dir)).toEqual([]);
  });

  it("still flags extra parens that are NOT a subquery: (auth.uid()) re-evaluates per row", () => {
    const dir = writeMigrations({
      "0001_rls.sql": `create policy orders_select_own on public.orders
  for select using (created_by = (auth.uid()));`,
    });
    expect(checkMigrationRlsInitplanStatic(dir)).toHaveLength(1);
  });

  it("does not let a preceding balanced pair fool the outward walk (fn() and auth.uid())", () => {
    // The paren pair of current_tenant_id() closes before the auth call — it is NOT an
    // enclosing wrapper, so the call is still bare and must be flagged.
    const dir = writeMigrations({
      "0001_rls.sql": `create policy notes_rw on public.notes
  for all using (tenant_id = public.current_tenant_id() and created_by = auth.uid());`,
    });
    expect(checkMigrationRlsInitplanStatic(dir)).toHaveLength(1);
  });

  it("treats an auth.* call inside an EXISTS (select …) subquery as hoisted — favor precision", () => {
    const dir = writeMigrations({
      "0001_rls.sql": `create policy items_select on public.items
  for select using (exists (select 1 from public.members m where m.user_id = auth.uid()));`,
    });
    expect(checkMigrationRlsInitplanStatic(dir)).toEqual([]);
  });

  it("stays silent on policies with no auth.* call at all", () => {
    const dir = writeMigrations({
      "0001_rls.sql": `create policy notes_rw on public.notes
  for all using (tenant_id = public.current_tenant_id());`,
    });
    expect(checkMigrationRlsInitplanStatic(dir)).toEqual([]);
  });

  it("rolls both clauses of one policy into a single finding", () => {
    const dir = writeMigrations({
      "0001_rls.sql": `create policy notes_rw on public.notes
  for all using (created_by = auth.uid()) with check (created_by = auth.uid());`,
    });
    const findings = checkMigrationRlsInitplanStatic(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain("auth.uid() in USING");
    expect(findings[0]!.evidence).toContain("auth.uid() in WITH CHECK");
  });

  it("returns nothing when the target has no migrations at all", () => {
    root = mkdtempSync(join(tmpdir(), "harvey-initplan-"));
    expect(checkMigrationRlsInitplanStatic(root)).toEqual([]);
  });

  it("clears a bare-call policy that a LATER migration rewrote with the (select …) wrapper (#937)", () => {
    const dir = writeMigrations({
      "0001_rls.sql": "create policy orders_select_own on public.orders for select using (created_by = auth.uid());",
      "0002_fix.sql": [
        "drop policy orders_select_own on public.orders;",
        "create policy orders_select_own on public.orders for select using (created_by = (select auth.uid()));",
      ].join("\n"),
    });
    expect(checkMigrationRlsInitplanStatic(dir)).toEqual([]);
  });
});
