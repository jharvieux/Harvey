// Volume rollup for the rendered deliverable (#935). Measured on crbnos/carbon (2026-07-24,
// docs/design/carbon-scale-measurement.md): the free source tier produced 8,027 counted findings on
// one target — 3,251 M4 clones alone — and a report that renders one card per finding stops being a
// deliverable at that volume (the client's reaction to a 3,251-row duplication table is to stop
// reading; Playwright's PDF pass was never designed against it either).
//
// DECISION (#935): roll up BY SHAPE at the presentation layer, never in the data. The precedent is
// #267's handrolled-indicator rule, generalized: repeats of the same shape (same taxonomy + same
// severity) above a threshold render as ONE group — the top few instances in full, the remainder
// disclosed BY COUNT with every location still present in the HTML (a collapsed <details>, which
// prints as its summary line in the PDF) and in the machine-readable findings.json/SARIF exports.
// The underlying Finding[] stays one row per occurrence; nothing here drops or rewrites a finding.
//
// The no-silent-cap invariant (CLAUDE.md's coverage guard, applied to presentation): the number
// withheld from individual rendering is PART OF THE OUTPUT. Every group states count = shown +
// withheld, and rollupFindings preserves every input finding exactly once — the tests in
// src/report-rollup.test.ts hold both invariants.
//
// Plain .mjs (not src/*.ts) because report-template/render.mjs consumes it directly at render time;
// TS callers/tests get types from rollup.d.mts (same pattern as tools/pii-classify.mjs).

// A (taxonomy, severity) shape with MORE than this many findings rolls up. Small groups render
// unchanged — the threshold exists for the carbon shape (thousands of one taxonomy), not to
// compress a 12-finding report.
export const ROLLUP_THRESHOLD = 10;

// How many of a rolled-up group's findings render as full cards (the group is pre-sorted by the
// caller — severity/hotspot/BFTB — so these are its highest-priority members).
export const ROLLUP_REPRESENTATIVES = 5;

// The action plan (every Critical/High + BFTB>75) is a table, so it tolerates more rows than the
// card body — but 600 rows is still not an action plan. Beyond this, rows are withheld BY COUNT
// (capActionPlan returns the number, the renderer prints it).
export const ACTION_PLAN_MAX_ROWS = 40;

const shapeKey = (f) => `${f.taxonomy}\u0000${f.severity}\u0000${f.assessment?.disposition ?? "legacy"}`;

// findings: the renderer's already-sorted list. Returns presentation items in the same order:
// { kind: "finding", finding } for members of small shapes, and — at the position of a large
// shape's first (highest-ranked) member — a single { kind: "group", ... } carrying the whole
// shape: representatives (rendered in full) + withheld (rendered as a count + location list).
export function rollupFindings(findings, opts = {}) {
  const threshold = opts.threshold ?? ROLLUP_THRESHOLD;
  const representatives = opts.representatives ?? ROLLUP_REPRESENTATIVES;

  const byShape = new Map();
  for (const f of findings) {
    const key = shapeKey(f);
    const list = byShape.get(key) ?? [];
    list.push(f);
    byShape.set(key, list);
  }

  const items = [];
  const emitted = new Set();
  for (const f of findings) {
    const key = shapeKey(f);
    const group = byShape.get(key);
    if (group.length <= threshold) {
      items.push({ kind: "finding", finding: f });
      continue;
    }
    if (emitted.has(key)) continue; // group already emitted at its first member's position
    emitted.add(key);
    items.push({
      kind: "group",
      taxonomy: f.taxonomy,
      severity: f.severity,
      category: f.category,
      disposition: f.assessment?.disposition ?? "legacy",
      count: group.length,
      representatives: group.slice(0, representatives),
      withheld: group.slice(representatives),
    });
  }
  return items;
}

// The action-plan cap: never silent — withheldCount is the number of rows that did NOT make the
// table, for the renderer to print alongside it.
export function capActionPlan(actions, max = ACTION_PLAN_MAX_ROWS) {
  if (actions.length <= max) return { shown: actions, withheldCount: 0 };
  return { shown: actions.slice(0, max), withheldCount: actions.length - max };
}
