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
});
