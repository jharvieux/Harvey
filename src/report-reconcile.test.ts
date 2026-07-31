// #1158: the last two seams before the client's eyes — dedup and the JSON→report renderer.
//
//   1. dedupeFindings (src/audit-report.ts) DROPS byte-identical duplicates. If it collapsed
//      DISTINCT near-duplicates (same rule, different location/tenant/occurrence — the #935/#1081
//      shape) it would silently remove real findings while the conservation ledger счита them
//      legitimately "deduped". These tests pin that it collapses only byte-identical rows and never
//      over-collapses a distinct set.
//   2. buildHtml (report-template/render.mjs) partitions every finding into exactly one rendered
//      section (live / N/A / review-flagged) — #1083. A finding in findings.json that lands in no
//      section is a silent client-facing drop. reconcileRender walks the document and asserts each
//      finding reaches the rendered HTML; the negative controls prove it FAILS LOUD when one doesn't.
//
// Deterministic (no Chromium): buildHtml produces the HTML the PDF is printed from, so a finding
// present in the HTML is present in the deliverable. The real end-to-end PDF render was exercised
// manually against a 22-finding synthetic fixture during #1158; this pins the invariant in CI.

import { describe, expect, it } from "vitest";
import { dedupeFindings } from "./audit-report.js";
import { validateFindings } from "./findings.js";
import type { Finding, FindingsDocument } from "./findings.js";
import { buildHtml } from "../report-template/render.mjs";
import { detectAppRouterFindings } from "./detectors/app-router.js";

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: "F-1", title: "A finding", severity: "High", confidence: "Confirmed",
  category: "Security", taxonomy: "M1-RULE", location: "src/a.ts:1", status: "Open",
  evidence: "ev", impact: "imp", fix: "fix", value: 3, ease: 3, safety: 3, ...over,
});

const doc = (findings: Finding[], over: Partial<FindingsDocument> = {}): FindingsDocument => ({
  meta: {
    client: "SYNTHETIC", subtitle: "reconcile", date: "2026-07-26", commit: "abc1234", auditor: "Harvey",
    confidential: false, overallHealth: 6, tenantIsolation: "Verified", authModel: "Supabase",
    headline: "test", scope: "synthetic", methodology: "ten modules", outOfScope: "infra",
  },
  findings,
  ...over,
});

// The renderer's own partition (report-template/render.mjs buildHtml): a live/N/A finding renders by
// id; a reviewFlagOnly finding renders by location (the review-for-nested-PII table has no id cell).
// Returns the findings whose identifying token is absent from the HTML — i.e. silently dropped.
function reconcileRender(document: FindingsDocument, html: string): string[] {
  return document.findings
    .filter((f) => !html.includes(f.reviewFlagOnly ? f.location : f.id))
    .map((f) => f.id);
}

describe("dedupeFindings — collapses only byte-identical rows (#1158)", () => {
  it("keeps distinct near-duplicates: same rule/taxonomy/severity, DIFFERENT location (#935/#1081)", () => {
    const input = [
      finding({ id: "F-1", taxonomy: "M1-SECRET", location: "src/a.ts:1" }),
      finding({ id: "F-2", taxonomy: "M1-SECRET", location: "src/b.ts:2" }),
      finding({ id: "F-3", taxonomy: "M1-SECRET", location: "src/c.ts:3" }),
    ];
    const out = dedupeFindings(input);
    expect(out).toHaveLength(3);
    expect(out.map((f) => f.id).sort()).toEqual(["F-1", "F-2", "F-3"]);
  });

  it("keeps findings that differ only by a single field (tenant/occurrence), never over-collapsing", () => {
    const input = [
      finding({ id: "F-1", location: "app/route.ts:10", evidence: "tenant A" }),
      finding({ id: "F-2", location: "app/route.ts:10", evidence: "tenant B" }),
    ];
    expect(dedupeFindings(input)).toHaveLength(2);
  });

  it("collapses TRUE byte-identical duplicates (the shared-CLI double-capture case)", () => {
    const dup = finding({ id: "F-DUP", taxonomy: "M6-X", location: "src/x.ts:9" });
    const out = dedupeFindings([dup, { ...dup }, { ...dup }]);
    expect(out).toHaveLength(1);
    expect(out[0]?.id).toBe("F-DUP");
  });

  it("preserves every DISTINCT finding while collapsing an interleaved identical dup", () => {
    const a = finding({ id: "F-A", location: "1" });
    const b = finding({ id: "F-B", location: "2" });
    const c = finding({ id: "F-C", location: "3" });
    const out = dedupeFindings([a, b, { ...a }, c, { ...b }]);
    // 3 distinct survive; 2 byte-identical repeats collapse — no distinct finding lost.
    expect(out.map((f) => f.id)).toEqual(["F-A", "F-B", "F-C"]);
  });
});

describe("findings.json → rendered report delivers every finding (#1158)", () => {
  // A synthetic document exercising all three render partitions plus a #935 rollup group.
  const live = [
    finding({ id: "F-CRIT", severity: "Critical", taxonomy: "M1-SQLI", location: "src/a.ts:1" }),
    finding({ id: "F-MED", severity: "Medium", confidence: "Review", taxonomy: "M7-N1", location: "src/c.ts:3", category: "Performance" }),
    finding({ id: "F-LOW", severity: "Low", confidence: "Likely", taxonomy: "M5-DEAD", location: "src/d.ts:4", category: "Maintainability" }),
  ];
  const nearDupes = [1, 2, 3].map((i) =>
    finding({ id: `F-DUP-${i}`, taxonomy: "M1-SECRET", location: `src/dup${i}.ts:${i}` }),
  );
  const rollup = Array.from({ length: 12 }, (_, i) =>
    finding({ id: `F-CLONE-${i + 1}`, severity: "Low", confidence: "Likely", taxonomy: "M4-CLONE", location: `src/clone${i + 1}.ts:${i + 1}`, category: "Maintainability" }),
  );
  const na = finding({ id: "F-NA", severity: "Info", confidence: "N/A", taxonomy: "M1-RLS", location: "n/a", note: "N/A by architecture" });
  const reviewFlag = finding({ id: "F-RF", severity: "Low", confidence: "Review", taxonomy: "M10-OPAQUE", location: "public.events", category: "Data", reviewFlagOnly: true, reviewFlagColumns: ["payload"] });
  const all = [...live, ...nearDupes, ...rollup, na, reviewFlag];
  const document = doc(all);

  it("the fixture is a valid findings document (so the render invariant is tested on real input)", () => {
    expect(validateFindings(document)).toEqual({ ok: true, errors: [] });
  });

  it("renders EVERY finding — count in == count reconciled, no silent drop", () => {
    const html = buildHtml(document);
    expect(reconcileRender(document, html)).toEqual([]);
  });

  it("a rolled-up group's withheld findings are still present in the HTML (disclosed, not dropped)", () => {
    const html = buildHtml(document);
    // 12 M4-CLONE findings roll up to 5 cards + 7 withheld; every withheld id is in the <details>.
    for (const f of rollup) expect(html).toContain(f.id);
    expect(html).toContain("7 more Low finding(s) of this shape are not individually rendered");
  });

  it("NEGATIVE CONTROL: reconcile FAILS LOUD when a finding renders in no section", () => {
    // The pre-#1083 drop shape: reviewFlagOnly with no columns and confidence !== "N/A" matches none
    // of the three render partitions, so buildHtml emits it nowhere. reconcileRender must catch it.
    const ghost = finding({ id: "F-GHOST", confidence: "Review", taxonomy: "M10-X", location: "ghost.loc", reviewFlagOnly: true });
    const withGhost = doc([...live, ghost]);
    const html = buildHtml(withGhost);
    expect(reconcileRender(withGhost, html)).toEqual(["F-GHOST"]);
  });

  it("validateFindings is the guard: it rejects the no-section finding at the door", () => {
    const ghost = finding({ id: "F-GHOST", confidence: "Review", location: "ghost.loc", reviewFlagOnly: true });
    const result = validateFindings(doc([ghost]));
    expect(result.ok).toBe(false);
    expect(result.errors.some((e) => e.includes("renders in no report section"))).toBe(true);
  });
});

// #1441 criterion 4. The row is emitted by the real detector, carried through validateFindings, and
// asserted in the HTML the PDF is printed from — not in the assembled JSON. #1433 found that every
// `confidence: "N/A"` row was having its reason replaced by "Not applicable in context." at render,
// so "the detector emits it" is not evidence the client ever sees it (#1435 tracks the general
// gate; this pins the one row #1441 exists to deliver).
describe("the M9 waterfall scope row reaches the RENDERED report, population intact (#1441)", () => {
  // A real suppressed pair: an early return on the first result between two queries.
  const SUPPRESSED_PAIR = `export default async function Page() {
  const { data: team } = await supabase.from("teams").select("id").single();
  if (!team) return null;
  const { data: settings } = await supabase.from("settings").select("theme").single();
  return null;
}
`;
  const scopeRow = detectAppRouterFindings([{ path: "app/dashboard/page.tsx", text: SUPPRESSED_PAIR }]).find(
    (f) => f.taxonomy === "M9 — Data-fetching waterfall — scope",
  );

  it("the detector really emits it (so the render assertion below is about a live row)", () => {
    expect(scopeRow).toBeDefined();
    expect(scopeRow?.title).toContain("1 of 1 adjacent query pair excluded by policy");
  });

  it("it is a valid finding — nothing rejects it before the renderer sees it", () => {
    expect(validateFindings(doc([finding(), scopeRow!]))).toEqual({ ok: true, errors: [] });
  });

  it("its population survives into the HTML, and is NOT replaced by 'Not applicable in context.'", () => {
    const document = doc([finding(), scopeRow!]);
    const html = buildHtml(document);
    expect(reconcileRender(document, html)).toEqual([]);
    expect(html).toContain("1 adjacent awaited-query pair was examined for parallelisability");
    expect(html).toContain("EXCLUDED BY POLICY");
    expect(html).not.toContain("Not applicable in context.");
  });
});

// #1262 criterion 2, the sibling of the block above. That criterion — "confirm it appears in a
// rendered report" — was met once, by hand, through a real render and `pdftotext`. A one-time proof
// is not a gate: the row's reason could go back to "Not applicable in context." tomorrow and the
// whole suite would stay green, which is the #1435 shape the block above exists to stop for the
// waterfall row. Same three assertions, this time over the retry row.
describe("the M9 uncapped-retry scope row reaches the RENDERED report, sub-shape counts intact (#1262)", () => {
  const UNCAPPED_RETRY = `export async function GET() {
  let done = false;
  while (!done) {
    try { await fetch("https://example.com"); done = true; } catch (e) {}
  }
  return new Response("ok");
}
`;
  const scopeRow = detectAppRouterFindings([{ path: "app/api/sync/route.ts", text: UNCAPPED_RETRY }]).find(
    (f) => f.taxonomy === "M9 — Uncapped retry/fan-out — scope",
  );

  it("the detector really emits it (so the render assertion below is about a live row)", () => {
    expect(scopeRow).toBeDefined();
    expect(scopeRow?.confidence).toBe("N/A");
  });

  it("it is a valid finding — nothing rejects it before the renderer sees it", () => {
    expect(validateFindings(doc([finding(), scopeRow!]))).toEqual({ ok: true, errors: [] });
  });

  it("its sub-shape list survives into the HTML, and is NOT replaced by 'Not applicable in context.'", () => {
    const document = doc([finding(), scopeRow!]);
    const html = buildHtml(document);
    expect(reconcileRender(document, html)).toEqual([]);
    expect(html).toContain("route/edge handler");
    // #1440's requirement that the sub-shape list be EXHAUSTIVE is what the client actually reads.
    expect(html).toContain("FOUR sub-shapes were NOT fully assessed");
    expect(html).not.toContain("Not applicable in context.");
  });
});
