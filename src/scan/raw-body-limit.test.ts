import { describe, expect, it } from "vitest";
import { detectRawBodyNoLimitFindings } from "./raw-body-limit.js";

// #1200's second shape — a raw `req.on("data", …)` accumulator with no byte ceiling. Single-handler
// heuristic (disclosed in the finding's evidence); each test below pins one edge of that scope.

const HANDLER = (body: string) => `import express from "express";
const app = express();
app.post("/ingest", (req, res) => {
${body}
});
export default app;
`;

describe("raw-body-limit (#1200 — unbounded req.on(\"data\") accumulator)", () => {
  it("flags an accumulator with no byte ceiling in the handler", () => {
    const text = HANDLER(`  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));
  req.on("end", () => res.json({ bytes: Buffer.concat(chunks).length }));`);
    const findings = detectRawBodyNoLimitFindings([{ path: "src/ingest.ts", text }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "Medium", precisionTier: "review", confidence: "Review" });
    expect(findings[0]?.taxonomy).toBe("Request body accumulated with no size limit");
    expect(findings[0]?.title).toContain("no size limit");
  });

  it("stays silent when a running total is compared against a maximum", () => {
    const text = HANDLER(`  const chunks: Buffer[] = [];
  let received = 0;
  req.on("data", (c: Buffer) => {
    received += c.length;
    if (received > 1000000) { req.destroy(); return; }
    chunks.push(c);
  });`);
    expect(detectRawBodyNoLimitFindings([{ path: "src/ingest.ts", text }])).toHaveLength(0);
  });

  it("stays silent when the ceiling is a named constant used only as an option", () => {
    const text = HANDLER(`  const chunks: Buffer[] = [];
  const bodyLimit = getRouteLimit();
  req.on("data", (c: Buffer) => chunks.push(c));
  guardStream(req, bodyLimit);`);
    expect(detectRawBodyNoLimitFindings([{ path: "src/ingest.ts", text }])).toHaveLength(0);
  });

  it("stays silent when the chunk is streamed out rather than buffered", () => {
    const text = HANDLER(`  const out = createWriteStream("/tmp/upload");
  req.on("data", (c: Buffer) => out.write(c));`);
    expect(detectRawBodyNoLimitFindings([{ path: "src/ingest.ts", text }])).toHaveLength(0);
  });

  it("stays silent on a non-request stream accumulating chunks", () => {
    const text = `const rows: Buffer[] = [];
export function load(stream) {
  stream.on("data", (c) => rows.push(c));
}
`;
    expect(detectRawBodyNoLimitFindings([{ path: "src/load.ts", text }])).toHaveLength(0);
  });

  it("DISCLOSED single-handler limitation: a ceiling enforced by middleware in another module is invisible, so this still fires — and the evidence says so", () => {
    const text = HANDLER(`  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));`);
    const findings = detectRawBodyNoLimitFindings([{ path: "src/ingest.ts", text }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("the enclosing handler in src/ingest.ts");
    expect(findings[0]?.evidence).toContain("OUTSIDE what this pass reads");
  });
});
