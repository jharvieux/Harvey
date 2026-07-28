// #1435 — DOES A FINDING'S OWN WORDS SURVIVE THE LAST SEAM?
//
// The conservation gate (#1064) asserts a planted finding is PRODUCED by its module and PRESENT in
// the assembled document. Assembly is upstream of rendering, and the deliverable the client reads is
// the rendered one. Everything between findings.json and the PDF was checked by nothing — and the
// defect that proves it shipped: `notApplicableSection` printed `note ?? "Not applicable in
// context."`, and NO row in the disclosure-row family sets `note`. So `M1-EXT-00`, `M1-LANG-00`,
// `SUP-SCOPE-00`, `SEM-SCOPE-00`, `SB-SCOPE-00`, `INFRA-SCOPE-00`, `M3-KNOWLEDGE-00`,
// `M10-ESCALATION-00` — the entire family whose job is to say WHAT could not be assessed and WHY —
// reached the client PDF as a title followed by the one sentence the coverage guard exists to
// prevent. The row was delivered; its content was not. Every ledger read clean.
//
// So this is not a check on one section. It is the general invariant, derived from the document
// rather than from a fixture's expectations:
//
//   For every delivered finding, EITHER its own words are in the rendered HTML, OR its omission is
//   disclosed AND COUNTED — and the count is the number actually omitted.
//
// Three renderer behaviours satisfy the second branch, and each is checked against its own
// arithmetic rather than against a magic string:
//
//   1. N/A rows        (notApplicableSection) — the reason must appear: `note` when a hand-authored
//                       applicability finding sets one, `evidence` otherwise, which is where every
//                       disclosure row states its scope.
//   2. live findings   (findingCard) — the Evidence line, including `Info` rows in the main body.
//                       An Info row is the easiest thing in the report to compress away, and it is
//                       the severity most of the disclosure family carries.
//   3. rolled-up shapes (groupCard, #935) — a shape above the rollup threshold renders its top
//                       members in full and withholds the rest BY COUNT. Those members legitimately
//                       have no Evidence line, so the check demands instead that each one's LOCATION
//                       is listed and that the disclosed withheld number EQUALS how many this
//                       function found missing. A renderer that dropped ten and said three fails.
//
// WHAT THIS DOES NOT COVER, said out loud rather than left to read as coverage: `resolvedSection`
// (prior-audit rows, which are not in `findings`), `fixSection` (the fix-handoff artifact), and the
// report's derived prose (coverage ledger, limitations, legal terms) — those have their own unit
// suites. `reviewFlagSection` IS covered, at the granularity that section renders: location plus
// each flagged column, because it deliberately does not restate evidence.

import { esc } from "../report-template/sections.mjs";
import type { Finding, FindingsDocument } from "./findings.js";

interface FidelityBreach {
  id: string;
  kind: "reason-dropped" | "undisclosed-omission" | "miscounted-rollup";
  detail: string;
}

const shapeKey = (f: Finding): string => `${f.taxonomy} ${f.severity}`;

/** Present as the renderer would have written it — escaped, so a `<` in evidence still matches. */
function rendered(html: string, text: string): boolean {
  return text.trim().length > 0 && html.includes(esc(text));
}

/**
 * Findings whose own words did not reach `html`, and whose absence is not disclosed and counted.
 * An empty array is the pass. Takes the ASSEMBLED document and the REAL rendered output — checking
 * this at the producer would re-prove what the conservation gate already proves, and would have
 * missed the defect that motivated it.
 */
export function renderFidelityBreaches(doc: FindingsDocument, html: string): FidelityBreach[] {
  const breaches: FidelityBreach[] = [];

  for (const f of doc.findings.filter((x) => x.confidence === "N/A")) {
    const reason = f.note ?? f.evidence;
    if (!rendered(html, reason)) {
      breaches.push({
        id: f.id,
        kind: "reason-dropped",
        detail: `not-assessed row rendered without its own reason. The report says WHAT was not assessed and not WHY, which reads as a clean bill of health for the thing it could not reach. Expected in report.html: "${reason.slice(0, 120)}"`,
      });
    }
  }

  // The renderer's own partition (buildHtml): reviewFlagOnly rows leave the findings body for the
  // nested-PII table, which lists location + columns rather than evidence.
  for (const f of doc.findings.filter((x) => x.reviewFlagOnly && x.confidence !== "N/A")) {
    const missing = [f.location, ...(f.reviewFlagColumns ?? [])].filter((t) => !rendered(html, t));
    if (missing.length > 0) {
      breaches.push({ id: f.id, kind: "reason-dropped", detail: `review-flagged row lost ${missing.join(", ")} — the reader is told a container may hold nested PII without being told which one` });
    }
  }

  const live = doc.findings.filter((x) => x.confidence !== "N/A" && !x.reviewFlagOnly);
  const absent = live.filter((f) => !rendered(html, f.evidence));

  // Group the absentees by the shape the renderer rolls up on, so the disclosed count can be
  // compared with the real one. A shape with absentees but no group block is a silent drop.
  const byShape = new Map<string, Finding[]>();
  for (const f of absent) byShape.set(shapeKey(f), [...(byShape.get(shapeKey(f)) ?? []), f]);

  for (const [shape, group] of byShape) {
    const first = group[0] as Finding;
    const unlisted = group.filter((f) => !rendered(html, f.location));
    if (unlisted.length > 0) {
      breaches.push({
        id: unlisted.map((f) => f.id).join(", "),
        kind: "undisclosed-omission",
        detail: `${unlisted.length} finding(s) of shape "${shape}" render neither their evidence nor their location — absorbed, not withheld. A count the reader cannot resolve to a place in their codebase is not a disclosure.`,
      });
    }
    // #935's contract: the withheld number is PART OF THE OUTPUT, and it must be the real one.
    const disclosed = new RegExp(String.raw`\b(\d+)\s+more\s+[^<]*?not individually rendered`, "g");
    const counts = [...html.matchAll(disclosed)].map((m) => Number(m[1]));
    if (!counts.includes(group.length)) {
      breaches.push({
        id: first.id,
        kind: "miscounted-rollup",
        detail: `${group.length} finding(s) of shape "${shape}" are not individually rendered, but no withheld-count line in the report states ${group.length}${counts.length ? ` (the report discloses ${counts.join(", ")})` : " — the report discloses no withheld count at all"}. A cap that understates what it capped is the silent cap #935 exists to prevent.`,
      });
    }
  }

  return breaches;
}
