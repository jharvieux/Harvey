import { describe, expect, it } from "vitest";
import { detectBolaCrossFileFindings } from "./bola-cross-file.js";
import type { SourceInput } from "../detectors/common.js";

// #1267 — the route → repository → query chain across a module boundary. The intent under test is
// that the detector reads BOTH ENDS: the near end decides whether the value is client-supplied, the
// far end decides whether the query is scoped by it and whether the repository checks. A test suite
// that only varied the handler would pass with the import resolution deleted, which is the exact
// recorded claim about the mechanical tier that this module was written to falsify.

const REPO = `import { admin } from "./supabaseAdmin";
export async function listOrders(tenantId) {
  return admin.from("orders").select("*").eq("tenant_id", tenantId);
}
export async function listOrdersChecked(tenantId, session) {
  if (tenantId !== session.tenantId) throw new Error("forbidden");
  return admin.from("orders").select("*").eq("tenant_id", tenantId);
}
`;

function handler(body: string): SourceInput[] {
  return [
    { path: "lib/order-repo.js", text: REPO },
    {
      path: "pages/api/orders.js",
      text: `import { getServerSession } from "next-auth";
import { listOrders, listOrdersChecked } from "../../lib/order-repo";
export default async function h(req, res) {
  const session = await getServerSession(req);
  if (!session) return res.status(401).end();
  ${body}
}
`,
    },
  ];
}

describe("bola-cross-file (#1267 — route → imported repository → ownership-scoped query)", () => {
  it("follows the import and flags a client-supplied id reaching the repository's query", () => {
    const findings = detectBolaCrossFileFindings(handler(`res.json(await listOrders(req.body.tenantId));`));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "High", precisionTier: "review" });
    expect(findings[0]?.taxonomy).toBe("Object-level authorization gap across a module boundary");
    expect(findings[0]?.evidence).toContain("lib/order-repo.js");
    // The finding points at the CALL SITE in the handler, not at line 1 of the file.
    expect(findings[0]?.location).toBe("pages/api/orders.js:6");
  });

  // The origin control: the far end is byte-identical, so only the near end can clear it.
  it("stays silent when the scoping id comes from the verified session", () => {
    expect(detectBolaCrossFileFindings(handler(`res.json(await listOrders(session.user.tenantId));`))).toEqual([]);
  });

  // The far-end control: the near end is byte-identical, so only reading the callee can clear it.
  it("stays silent when the REPOSITORY compares the id against the session", () => {
    expect(detectBolaCrossFileFindings(handler(`res.json(await listOrdersChecked(req.body.tenantId, session.user));`))).toEqual([]);
  });

  it("stays silent when the handler itself compares the request id against the session", () => {
    expect(
      detectBolaCrossFileFindings(
        handler(`if (req.body.tenantId !== session.user.tenantId) return res.status(403).end();
  res.json(await listOrders(req.body.tenantId));`),
      ),
    ).toEqual([]);
  });

  // An unauthenticated route is the missing-auth class; harvey-route-noauth owns it, and firing
  // here would double-count it (the #1062 masking shape reached through a second detector).
  it("stays silent on an unauthenticated route", () => {
    const files: SourceInput[] = [
      { path: "lib/order-repo.js", text: REPO },
      {
        path: "pages/api/orders.js",
        text: `import { listOrders } from "../../lib/order-repo";
export default async function h(req, res) {
  res.json(await listOrders(req.body.tenantId));
}
`,
      },
    ];
    expect(detectBolaCrossFileFindings(files)).toEqual([]);
  });

  // The RLS client still gates the row by policy, so an unscoped query there is not by itself a
  // bug — the same boundary bola-owner.ts draws.
  it("stays silent when the repository queries through the RLS client", () => {
    const files = handler(`res.json(await listOrders(req.body.tenantId));`);
    files[0]!.text = REPO.replace(/admin/g, "supabase");
    expect(detectBolaCrossFileFindings(files)).toEqual([]);
  });

  // The bound that separates this from bola-owner.ts, asserted rather than only described: if the
  // module does not resolve there is no far end to read, and the detector says nothing.
  it("stays silent when the import resolves to nothing (an external package)", () => {
    const files = handler(`res.json(await listOrders(req.body.tenantId));`);
    files[1]!.text = files[1]!.text.replace('"../../lib/order-repo"', '"@acme/order-repo"');
    expect(detectBolaCrossFileFindings(files)).toEqual([]);
  });
});
