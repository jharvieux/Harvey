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

  it("flags an unscoped service-role delete", () => {
    const del = positive.replace(`.select("*")`, `.delete()`);
    const findings = run(del);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain(".delete()");
  });

  it("still flags the read when the .eq column is not a tenant/owner column — an arbitrary filter is not a scoping predicate", () => {
    const statusFiltered = positive.replace(`.select("*")`, `.select("*").eq("status", "pending")`);
    expect(run(statusFiltered)).toHaveLength(1);
  });

  it("dedupes two unscoped sites on the SAME table in one file down to a single finding", () => {
    const twoSitesSameTable = `import { admin } from "../../lib/supabaseAdmin";
export const importInbound = inngest.createFunction({ id: "import-inbound" }, { event: "gmail/received" }, async ({ event }) => {
  const { data } = await admin.from("gmail_inbound_messages").select("*");
  await admin.from("gmail_inbound_messages").delete();
  return data;
});
`;
    expect(run(twoSitesSameTable)).toHaveLength(1);
  });

  it("flags each unscoped site separately when they hit DIFFERENT tables", () => {
    const twoTables = `import { admin } from "../../lib/supabaseAdmin";
export const importInbound = inngest.createFunction({ id: "import-inbound" }, { event: "gmail/received" }, async ({ event }) => {
  const { data: a } = await admin.from("gmail_inbound_messages").select("*");
  const { data: b } = await admin.from("sms_inbound_messages").select("*");
  return [a, b];
});
`;
    const findings = run(twoTables);
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.evidence).join(" ")).toContain("gmail_inbound_messages");
    expect(findings.map((f) => f.evidence).join(" ")).toContain("sms_inbound_messages");
  });

  it("does not double-count a chain that continues past the scoped verb with a further method call", () => {
    const chained = positive.replace(`.select("*")`, `.select("*").order("created_at")`);
    expect(run(chained)).toHaveLength(1);
  });

  it.each(["src/jobs/reconcile.ts", "src/queues/worker.ts", "src/workers/sync.ts"])(
    "flags the same unscoped read under the %s background-job path",
    (path) => {
      expect(run(positive, path)).toHaveLength(1);
    },
  );

  it("stays silent when the d091-allow annotation is a TRAILING comment on the statement", () => {
    const trailingAnnotated = positive.replace(
      `const { data } = await admin.from("gmail_inbound_messages").select("*");`,
      `const { data } = await admin.from("gmail_inbound_messages").select("*"); // ${"d091-allow:service-role-tenant"} — scoped by the job wrapper`,
    );
    expect(run(trailingAnnotated)).toHaveLength(0);
  });
});
