import { describe, expect, it } from "vitest";
import { detectBolaOwnerFindings } from "./bola-owner.js";

// #433 — near-miss shapes beyond the corpus pair (which calibration.test.ts scores against the
// committed fixtures). Each negative here differs from the positive by exactly one gate, so a
// single-gate regression fails a specific test rather than only the whole-target count.

const positive = `import { admin } from "../../../lib/supabaseAdmin";
import { getServerSession } from "next-auth";
export default async function handler(req, res) {
  const session = await getServerSession(req);
  if (!session) return res.status(401).json({ error: "unauthorized" });
  const { data } = await admin.from("invoices").select("*").eq("tenant_id", req.body.tenantId);
  res.status(200).json({ invoice: data });
}
`;

const file = (text: string, path = "pages/api/billing/invoice.js") => [{ path, text }];

describe("bola-owner (#433 — authenticated pages/api handler, service-role query scoped by a request-supplied owner id)", () => {
  it("flags the planted shape at review tier, with the ownership column in the evidence", () => {
    const findings = detectBolaOwnerFindings(file(positive));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "High", precisionTier: "review" });
    expect(findings[0]?.evidence).toContain("bola-body-owner");
    expect(findings[0]?.evidence).toContain("tenant_id");
  });

  it("stays silent when no session is bound — the unauthenticated surface belongs to the missing-auth/IDOR classes", () => {
    const noSession = positive.replace(/const session[\s\S]*?unauthorized" \}\);\n/, "");
    expect(detectBolaOwnerFindings(file(noSession))).toHaveLength(0);
  });

  it("stays silent on the plain (non-service) client — RLS policies still gate the query", () => {
    const rlsClient = positive.replaceAll("admin", "supabase");
    expect(detectBolaOwnerFindings(file(rlsClient))).toHaveLength(0);
  });

  it("stays silent when the handler compares the request id against the session's before querying", () => {
    const compared = positive.replace(
      "const { data }",
      `if (req.body.tenantId !== session.user.tenantId) return res.status(403).json({ error: "forbidden" });\n  const { data }`,
    );
    expect(detectBolaOwnerFindings(file(compared))).toHaveLength(0);
  });

  it("stays silent outside pages/api — the Server Action surface is detectClientSuppliedOwnerId's", () => {
    expect(detectBolaOwnerFindings(file(positive, "lib/billing.js"))).toHaveLength(0);
  });

  // #1269. The `pages/api/` segment is not itself a shipping guarantee: a vendored Next.js example
  // app or an e2e fixture tree carries it too, and measured 2026-07-31 this detector fired on the
  // planted shape at every path below exactly as it does at `pages/api/billing/invoice.js`.
  it.each([
    "e2e/pages/api/invoice.js",
    "examples/next-app/pages/api/invoice.js",
    "__tests__/pages/api/invoice.js",
    "docs/demo/pages/api/invoice.js",
    "pages/api/invoice.test.js",
  ])("stays silent for the same shape in the non-shipping path %s", (path) => {
    expect(detectBolaOwnerFindings(file(positive, path))).toHaveLength(0);
  });

  it("still flags the shape in a shipping pages/api route (scope control for the non-shipping exclusion)", () => {
    expect(detectBolaOwnerFindings(file(positive, "src/pages/api/billing/invoice.js"))).toHaveLength(1);
  });
});
