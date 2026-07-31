// #1295 — #984's unimplemented guardrail: "route to the review tier where a header is plausibly
// trusted. Do NOT let it introduce free-count FPs."
//
// Every case below is a shape MEASURED against the real ruleset before this pass existed (semgrep
// 1.164.0, 2026-07-30) — all four fired at ERROR + HIGH, i.e. the free count. The routed pair must
// land at review tier and the unrouted pair must stay at free count, so the test fails in BOTH
// directions: widening the platform-header set to arbitrary custom headers fails the last two,
// narrowing it to nothing fails the first two.

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { PLATFORM_HEADER_IMPACT_SUFFIX } from "./header-trust.js";
import { parseSemgrepFindings } from "./semgrep.js";

const HIGH_RULE = {
  extra: { severity: "ERROR", message: "Untrusted request input reaches a raw SQL string.", metadata: { confidence: "HIGH" } },
};

function tierOf(lines: string[], matchLine: number): { tier: string; impact: string } {
  const dir = mkdtempSync(join(tmpdir(), "harvey-header-trust-"));
  const file = join(dir, "route.ts");
  writeFileSync(file, lines.join("\n"));
  try {
    const findings = parseSemgrepFindings({
      results: [
        { check_id: "harvey-sql-injection-template", path: file, start: { line: matchLine }, end: { line: matchLine }, ...HIGH_RULE },
      ],
    });
    const finding = findings[0];
    if (finding === undefined) throw new Error("parseSemgrepFindings dropped the result");
    return { tier: finding.precisionTier ?? "(none)", impact: finding.impact };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("platform-set header trust routing (#1295)", () => {
  it("a Vercel-set geolocation header reaching a sink lands at review tier, with the reason on the finding", () => {
    const { tier, impact } = tierOf(
      [
        'import { headers } from "next/headers";',
        "export async function GET() {",
        '  const country = headers().get("x-vercel-ip-country");',
        "  return db.query(`SELECT * FROM stats WHERE country = '${country}'`);",
        "}",
      ],
      4,
    );
    expect(tier).toBe("review");
    expect(impact).toContain(PLATFORM_HEADER_IMPACT_SUFFIX);
  });

  it("a reverse-proxy-set x-real-ip reaching a sink lands at review tier", () => {
    expect(
      tierOf(
        [
          "module.exports = function handler(req, res) {",
          '  const ip = req.headers["x-real-ip"];',
          "  exec(`geoiplookup ${ip}`, (e, out) => res.end(out));",
          "}",
        ],
        3,
      ).tier,
    ).toBe("review");
  });

  it("a gateway-convention identity header is NOT platform-set and keeps its free-count tier", () => {
    const { tier, impact } = tierOf(
      [
        'import { headers } from "next/headers";',
        "export async function GET() {",
        '  const tenant = headers().get("x-tenant-id");',
        "  return db.query(`SELECT * FROM invoices WHERE tenant = '${tenant}'`);",
        "}",
      ],
      4,
    );
    expect(tier).toBe("high");
    expect(impact).not.toContain(PLATFORM_HEADER_IMPACT_SUFFIX);
  });

  it("an arbitrary custom header keeps its free-count tier", () => {
    expect(
      tierOf(
        [
          'import { headers } from "next/headers";',
          "export async function GET() {",
          '  const sort = headers().get("x-sort-order");',
          "  return db.query(`SELECT * FROM invoices ORDER BY ${sort}`);",
          "}",
        ],
        4,
      ).tier,
    ).toBe("high");
  });

  it("x-forwarded-for is NOT treated as platform-set — a proxy appends to it, so the client half survives", () => {
    expect(
      tierOf(
        [
          "module.exports = function handler(req, res) {",
          '  const fwd = req.headers["x-forwarded-for"];',
          "  return db.query(`SELECT * FROM audit WHERE ip = '${fwd}'`);",
          "}",
        ],
        3,
      ).tier,
    ).toBe("high");
  });

  it("a platform header alongside another request source in the same sink stays at free count", () => {
    expect(
      tierOf(
        [
          "module.exports = function handler(req, res) {",
          '  const ip = req.headers["x-real-ip"];',
          "  return db.query(`SELECT * FROM audit WHERE ip = '${ip}' AND q = '${req.query.q}'`);",
          "}",
        ],
        3,
      ).tier,
    ).toBe("high");
  });

  it("a platform header read directly at the sink, with no intermediate binding, still routes", () => {
    expect(
      tierOf(
        [
          'import { headers } from "next/headers";',
          "export async function GET() {",
          '  return db.query(`SELECT * FROM stats WHERE ray = \'${headers().get("cf-ray")}\'`);',
          "}",
        ],
        3,
      ).tier,
    ).toBe("review");
  });

  it("a finding with no platform header anywhere in the file is untouched", () => {
    expect(
      tierOf(
        [
          "module.exports = function handler(req, res) {",
          "  return db.query(`SELECT * FROM t WHERE q = '${req.query.q}'`);",
          "}",
        ],
        2,
      ).tier,
    ).toBe("high");
  });
});
