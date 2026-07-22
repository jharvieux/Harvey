import { describe, expect, it } from "vitest";
import { detectPgResponseExposureFindings } from "./pg-response-exposure.js";

// #701 (#663 remainder) — near-miss shapes beyond the corpus fixtures scored by
// calibration.test.ts. Each negative differs from a positive by exactly one gate, so a
// single-gate regression fails a specific test rather than only the whole-target count.

const file = (text: string, path = "lib/users.js") => [{ path, text }];

describe("pg-response-exposure (#701 — res.json(...) exposes a full sensitive row/object)", () => {
  describe("direct: a curated sensitive field is a literal property of the returned object", () => {
    const positive = `export function getUser(req, res) {
  const id = req.params.id;
  res.json({ id, email: "a@example.com", passwordHash: "x" });
}
`;

    it("flags the planted shape at review tier, naming the field", () => {
      const findings = detectPgResponseExposureFindings(file(positive));
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ severity: "High", precisionTier: "review" });
      expect(findings[0]?.evidence).toContain("pg-resjson-exposure-direct");
      expect(findings[0]?.evidence).toContain("passwordHash");
    });

    it("stays silent when the returned object only names ordinary DTO fields", () => {
      const safe = positive.replace('passwordHash: "x"', 'createdAt: "2026-01-01"');
      expect(detectPgResponseExposureFindings(file(safe))).toHaveLength(0);
    });

    it("stays silent on a bare 'token' field — a CSRF/share-link token is not curated in", () => {
      const benign = positive.replace('passwordHash: "x"', 'token: "share-link-abc"');
      expect(detectPgResponseExposureFindings(file(benign))).toHaveLength(0);
    });

    it("stays silent outside an Express-shaped (req, res) handler", () => {
      const noHandler = `export function buildDto(req) {
  return { id: req.params.id, passwordHash: "x" };
}
`;
      expect(detectPgResponseExposureFindings(file(noHandler))).toHaveLength(0);
    });
  });

  describe("spread: a same-function object literal that names a sensitive field is spread into res.json", () => {
    const positive = `export function getUser(req, res) {
  const user = { id: req.params.id, email: "a@example.com", refreshToken: "x" };
  res.json({ ...user });
}
`;

    it("flags the planted shape, naming the field", () => {
      const findings = detectPgResponseExposureFindings(file(positive));
      expect(findings).toHaveLength(1);
      expect(findings[0]?.evidence).toContain("pg-resjson-exposure-spread");
      expect(findings[0]?.evidence).toContain("refreshToken");
    });

    it("stays silent when the spread variable's own literal never names a sensitive field", () => {
      const safe = positive.replace('refreshToken: "x"', 'createdAt: "2026-01-01"');
      expect(detectPgResponseExposureFindings(file(safe))).toHaveLength(0);
    });

    it("stays silent when the spread variable is declared in a different function", () => {
      const crossFn = `const user = { id: 1, refreshToken: "x" };
export function getUser(req, res) {
  res.json({ ...user });
}
`;
      expect(detectPgResponseExposureFindings(file(crossFn))).toHaveLength(0);
    });
  });

  describe("select-star: a same-function SELECT * result flows straight into res.json", () => {
    const positive = `export async function getUser(req, res) {
  const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  res.json(result.rows[0]);
}
`;

    it("flags the planted shape", () => {
      const findings = detectPgResponseExposureFindings(file(positive));
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ severity: "Medium", precisionTier: "review" });
      expect(findings[0]?.evidence).toContain("pg-resjson-exposure-select-star");
    });

    it("flags the destructured-rows variant", () => {
      const destructured = `export async function getUser(req, res) {
  const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  res.json(rows[0]);
}
`;
      expect(detectPgResponseExposureFindings(file(destructured))).toHaveLength(1);
    });

    it("stays silent when the query selects an explicit column list, not *", () => {
      const narrowed = positive.replace("SELECT * FROM users", "SELECT id, email FROM users");
      expect(detectPgResponseExposureFindings(file(narrowed))).toHaveLength(0);
    });

    it("stays silent when the handler narrows the row before returning it", () => {
      const narrowedReturn = `export async function getUser(req, res) {
  const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  const { id, email } = result.rows[0];
  res.json({ id, email });
}
`;
      expect(detectPgResponseExposureFindings(file(narrowedReturn))).toHaveLength(0);
    });
  });
});
