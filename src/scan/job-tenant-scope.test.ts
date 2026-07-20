import { describe, expect, it } from "vitest";
import { detectJobTenantScopeFindings } from "./job-tenant-scope.js";

// #681 — a service-role query in a background-job path with NO tenant predicate. Each negative
// differs from the positive by exactly one gate (a tenant .eq, the allow annotation, the job
// path), so a single-gate regression fails a specific test rather than only the whole count.

const positive = `import { admin } from "../../lib/supabaseAdmin";
export const importInbound = inngest.createFunction({ id: "import-inbound" }, { event: "gmail/received" }, async ({ event }) => {
  const { data } = await admin.from("gmail_inbound_messages").select("*");
  return data;
});
`;

const run = (text: string, path = "src/inngest/import-inbound.ts") => detectJobTenantScopeFindings([{ path, text }]);
const TAX = "Service-role query in a background-job path with no tenant predicate";

describe("job-tenant-scope (#681 — unscoped service-role query in a background-job path)", () => {
  it("flags the unfiltered service-role read at review/High, naming the table", () => {
    const findings = run(positive);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "High", precisionTier: "review", taxonomy: TAX });
    expect(findings[0]?.evidence).toContain("job-tenant-scope");
    expect(findings[0]?.evidence).toContain("gmail_inbound_messages");
  });

  it("stays silent when the query carries a tenant .eq predicate", () => {
    const scoped = positive.replace(`.select("*")`, `.select("*").eq("tenant_id", event.data.tenantId)`);
    expect(run(scoped)).toHaveLength(0);
  });

  it("stays silent when a tenant filter is expressed via .match", () => {
    const matched = positive.replace(`.select("*")`, `.select("*").match({ tenant_id: event.data.tenantId })`);
    expect(run(matched)).toHaveLength(0);
  });

  it("stays silent when the site carries the d091-allow annotation", () => {
    const annotated = positive.replace(
      "  const { data }",
      "  // d091-allow:service-role-tenant — scoped by the job wrapper\n  const { data }",
    );
    expect(run(annotated)).toHaveLength(0);
  });

  it("stays silent on the plain (non-service) client — RLS still gates the read", () => {
    expect(run(positive.replaceAll("admin", "supabase"))).toHaveLength(0);
  });

  it("stays silent for the same unfiltered read OUTSIDE a background-job path", () => {
    expect(run(positive, "src/app/dashboard/page.tsx")).toHaveLength(0);
  });

  it("flags an unscoped service-role update in a cron path", () => {
    const cron = `import { admin } from "../../../lib/supabaseAdmin";
export async function GET() {
  await admin.from("subscriptions").update({ status: "expired" });
}
`;
    const findings = detectJobTenantScopeFindings([{ path: "app/api/cron/expire/route.ts", text: cron }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("update");
  });

  it("does not flag an insert (the payload names the tenant, it doesn't select whose rows)", () => {
    const insert = positive.replace(`.select("*")`, `.insert({ subject: event.data.subject })`);
    expect(run(insert)).toHaveLength(0);
  });
});
