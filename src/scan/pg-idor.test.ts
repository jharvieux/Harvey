import { describe, expect, it } from "vitest";
import { detectPgIdorFindings } from "./pg-idor.js";

// #663 — near-miss shapes beyond the corpus pair (which calibration.test.ts scores against the
// committed fixtures). Each negative differs from the positive by exactly one gate, so a
// single-gate regression fails a specific test rather than only the whole-target count.

const positive = `export function getOrder(req, res) {
  const role = req.user.role;
  const order = findOrderById(req.params.id);
  res.json({ order, role });
}
`;

const file = (text: string, path = "lib/orders.js") => [{ path, text }];

describe("pg-idor (#663 — authenticated Express handler passes a client-supplied id into a read-by-id repo function)", () => {
  it("flags the planted shape at review tier, naming the sink function", () => {
    const findings = detectPgIdorFindings(file(positive));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "High", precisionTier: "review" });
    expect(findings[0]?.evidence).toContain("pg-idor-repo-fn");
    expect(findings[0]?.evidence).toContain("findOrderById");
  });

  it("stays silent when the handler compares the caller's identity against the row before returning it", () => {
    const compared = positive.replace(
      "  res.json({ order, role });",
      `  if (order.userId !== req.user.id) return res.status(403).json({ error: "forbidden" });\n  res.json({ order, role });`,
    );
    expect(detectPgIdorFindings(file(compared))).toHaveLength(0);
  });

  it("stays silent when no req.user/session.user is ever read — the unauthenticated surface belongs to a different class", () => {
    const noAuth = positive.replace("  const role = req.user.role;\n", "");
    expect(detectPgIdorFindings(file(noAuth))).toHaveLength(0);
  });

  it("stays silent when the sink function name doesn't match the read-by-id gate", () => {
    const benignName = positive.replace("findOrderById(req.params.id)", "logOrderAccess(req.params.id)");
    expect(detectPgIdorFindings(file(benignName))).toHaveLength(0);
  });

  it("stays silent outside an Express-shaped (req, res) handler", () => {
    const noHandler = `function findOrderById(id) { return db.orders.get(id); }
export function process(req) {
  const role = req.user.role;
  return findOrderById(req.params.id);
}
`;
    expect(detectPgIdorFindings(file(noHandler))).toHaveLength(0);
  });

  // #1269. Before this gate the SAME shape fired identically at `tests/orders.test.js` and
  // `src/lib/orders.js` (measured 2026-07-31), and this detector reads the WHOLE source tree —
  // 631 of the 977 files it read across the three pinned M1-precision clones are non-shipping.
  // The shipping control below is what keeps the exclusion from reading as "detector gone dark".
  it.each(["tests/orders.test.js", "e2e/orders.js", "examples/basic/orders.js", "docs/samples/orders.js", "src/orders.test.js"])(
    "stays silent for the same shape in the non-shipping path %s",
    (path) => {
      expect(detectPgIdorFindings(file(positive, path))).toHaveLength(0);
    },
  );

  it("still flags the shape in shipping source (scope control for the non-shipping exclusion)", () => {
    expect(detectPgIdorFindings(file(positive, "src/routes/orders.js"))).toHaveLength(1);
  });
});
