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

  it("states the check only recognises _id-suffixed columns, so an empty list isn't proof of a clean result (#281)", () => {
    const dir = writeMigrations(
      "create table public.notes (id uuid primary key, tenant_id uuid not null);\n" +
        "create policy n_all on public.notes for all using (tenant_id = current_tenant()) with check (tenant_id = current_tenant());",
    );
    expect(model(dir)!.evidence).toContain('only matches column names ending in "_id"');
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
});
