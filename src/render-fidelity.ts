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
// Since #825 "its own words" includes a VERIFIED suggested fix, on any finding whose card is
// individually rendered — a diff is the most concrete thing the paid tier ships, and it reached
// filed tickets while the report showed only the prose fix.
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
//   4. the coverage ledger (coverageSection, #1555) — not a finding, and the only place the report
//                       states what each module reached. It has no rollup to fall back on, so BOTH
//                       free-text fields a row carries (`detail` = what ran, `reason` = why it fell
//                       short) must appear; the branch that chose one by status dropped the other.
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
  kind: "reason-dropped" | "undisclosed-omission" | "miscounted-rollup" | "fix-diff-dropped" | "coverage-text-dropped";
  detail: string;
}

const shapeKey = (f: Finding): string => `${f.taxonomy} ${f.severity}`;

/** Present as the renderer would have written it — escaped, so a `<` in evidence still matches. */
function rendered(html: string, text: string): boolean {
  return text.trim().length > 0 && html.includes(esc(text));
}

/**
 * #1627 — IDENTITY BY FINDING, NOT BY STRING. `rendered(html, …)` asks whether some text is anywhere
 * in the document, and that is not the same question as whether THIS finding's words reached the
 * client. Two findings of one shape routinely carry a BYTE-IDENTICAL evidence string — the text is a
 * template over the shape, not over the name — so when the rollup renders one as a representative
 * and withholds the other, the withheld one's evidence is "present", attributed to its twin. It then
 * drops out of the absentee set, the rollup arithmetic compares a short count against the renderer's
 * correct one, and the gate reports a miscount that does not exist. MEASURED 2026-07-31 on a real
 * ten-module deliverable over targets/calibration: shape `M1 — Multi-tenant security High`, 11
 * members, 5 scored absent against 6 actually withheld, because
 * `SB-RLS-POLICY-public.nocode_invoices.nocode_invoices_read` and
 * `SB-RLS-POLICY-public.documents.documents_select_all` are both `using (true)` policies with the
 * same finding text. That is #1062's masking shape reached through the render seam: one finding's
 * output standing in for another's.
 *
 * The POPULATION, before anyone reads this as a corner case, measured on that same 895-finding
 * deliverable: 430 live findings share an evidence string with at least one twin, across 78 distinct
 * strings. Roughly half the document is exposed to the collision — which is what you get when the
 * finding text is written per shape and the shape is the thing the rollup groups on.
 *
 * The document already carries the attribution, so this READS it rather than reconstructing it:
 * `findingCard`, `groupCard`'s withheld `<details>` list and `notApplicableSection` all open a row
 * with `<span class="fid">ID</span>`. A region runs from one such marker to the next, bounded by the
 * next `<h2>` so the LAST row on the page does not absorb the coverage table and the legal terms.
 * A finding with no marker at all has an empty region, which is the correct answer — nothing in the
 * report is attributed to it.
 *
 * Keyed by the ESCAPED id, because that is what the renderer wrote; callers look up `esc(f.id)`.
 * `resolvedSection` prefixes its marker with `✓ `, which is stripped so a prior-audit row lands on
 * its own id rather than a near-miss key.
 */
function regionsById(html: string): Map<string, string> {
  const marks = [...html.matchAll(/<span class="fid"[^>]*>([^<]*)<\/span>/g)];
  const regions = new Map<string, string>();
  marks.forEach((m, i) => {
    const start = (m.index ?? 0) + m[0].length;
    const nextMarker = marks[i + 1]?.index ?? html.length;
    const nextHeading = html.indexOf("<h2>", start);
    const end = Math.min(nextMarker, nextHeading === -1 ? html.length : nextHeading);
    const id = (m[1] ?? "").replace(/^✓\s*/, "").trim();
    regions.set(id, `${regions.get(id) ?? ""}\n${html.slice(start, end)}`);
  });
  return regions;
}

/**
 * Findings whose own words did not reach `html`, and whose absence is not disclosed and counted.
 * An empty array is the pass. Takes the ASSEMBLED document and the REAL rendered output — checking
 * this at the producer would re-prove what the conservation gate already proves, and would have
 * missed the defect that motivated it.
 */
export function renderFidelityBreaches(doc: FindingsDocument, html: string): FidelityBreach[] {
  const breaches: FidelityBreach[] = [];
  const regions = regionsById(html);
  /** The part of the report the report itself attributes to this finding. Empty ⇒ it rendered no row. */
  const region = (f: Finding): string => regions.get(esc(f.id)) ?? "";

  // #1555 — the same invariant one table over. The COVERAGE LEDGER is not a finding, and it is the
  // one place in the report that states what each module did and did not reach; `coverageSection`
  // rendered exactly one of a row's two free-text fields, chosen by status, so a `partial` row's
  // `detail` (the #502 "no M3 hotspot focus" warning among it) was in findings.json and absent from
  // the report. A ledger row has no rollup and no withheld count to fall back on: either its words
  // are in that table or the client never sees them.
  //
  // Scoped to the table on purpose, not to the whole document. The draft legal block re-states every
  // non-`ran` row's REASON, so a whole-document check would have been satisfied by that copy while
  // the coverage table said nothing — and it would still have measured `detail` at zero coverage,
  // because nothing else in the report carries it. A missing section is itself the loudest breach:
  // no table ⇒ every row reports its text dropped.
  const coverage = doc.coverage ?? [];
  if (coverage.length > 0) {
    const table = /<h2>Module coverage<\/h2>[\s\S]*?<\/table>/.exec(html)?.[0] ?? "";
    for (const r of coverage) {
      const dropped = ([["detail", r.detail], ["reason", r.reason]] as const).filter(([, t]) => t && t.trim() && !rendered(table, t));
      if (dropped.length > 0) {
        breaches.push({
          id: `${r.module}${r.instance ? ` (${r.instance})` : ""}`,
          kind: "coverage-text-dropped",
          detail: `coverage row rendered without its ${dropped.map(([field]) => field).join(" and ")}${table ? "" : " (no Module coverage table in the report at all)"}. The ledger is where the report says what a module did and did not reach; text dropped here reads as a fuller run than happened. Expected in the coverage table: ${dropped.map(([field, t]) => `${field}="${(t as string).slice(0, 120)}"`).join(", ")}`,
        });
      }
    }
  }

  for (const f of doc.findings.filter((x) => x.confidence === "N/A")) {
    const reason = f.note ?? f.evidence;
    if (!rendered(region(f), reason)) {
      breaches.push({
        id: f.id,
        kind: "reason-dropped",
        detail: `not-assessed row rendered without its own reason. The report says WHAT was not assessed and not WHY, which reads as a clean bill of health for the thing it could not reach. Expected in report.html: "${reason.slice(0, 120)}"`,
      });
    }
  }

  // The renderer's own partition (buildHtml): reviewFlagOnly rows leave the findings body for the
  // nested-PII table, which lists location + columns rather than evidence.
  //
  // This is the ONE path still scored against the whole document rather than the finding's own
  // region, and it is a real residual, not an oversight: `reviewFlagSection` emits a plain `<tr>`
  // with no `<span class="fid">`, so the report attributes nothing to a row's id and there is no
  // region to read. Two nested-PII rows on the same location with the same columns would therefore
  // still cover for each other. Closing it means adding the marker to that section — a renderer
  // change, tracked by #1730. MEASURED on the same 895-finding deliverable: 11 rows reach this path
  // and no two share a (location, columns) pair, so nothing is mis-scored today. A live path with no
  // collision yet, not an empty one — the first draft of #1730 said "zero rows" and was wrong.
  for (const f of doc.findings.filter((x) => x.reviewFlagOnly && x.confidence !== "N/A")) {
    const missing = [f.location, ...(f.reviewFlagColumns ?? [])].filter((t) => !rendered(html, t));
    if (missing.length > 0) {
      breaches.push({ id: f.id, kind: "reason-dropped", detail: `review-flagged row lost ${missing.join(", ")} — the reader is told a container may hold nested PII without being told which one` });
    }
  }

  const live = doc.findings.filter((x) => x.confidence !== "N/A" && !x.reviewFlagOnly);
  const absent = live.filter((f) => !rendered(region(f), f.evidence));

  // #825 — the same invariant applied to the paid tier's most concrete deliverable. A verified
  // `suggestedFix` is a patch a client may apply; it reached filed tickets and, until this check,
  // nothing asserted it reached the REPORT. Scoped to findings whose card is individually rendered:
  // a finding withheld by the #935 rollup legitimately renders no card, and its withheld-count line
  // already states that its full evidence and fix live in findings.json.
  const carded = new Set(live.filter((f) => !absent.includes(f)).map((f) => f.id));
  for (const f of live) {
    const diff = f.suggestedFix?.verified ? f.suggestedFix.diff.replace(/\n+$/, "") : "";
    if (!diff.trim() || !carded.has(f.id) || rendered(region(f), diff)) continue;
    breaches.push({
      id: f.id,
      kind: "fix-diff-dropped",
      detail: `a VERIFIED suggested fix is attached to this finding and its diff is absent from the rendered report. The client is shown the prose fix while the applicable patch — the thing the paid tier is sold on — is dropped at the last seam.`,
    });
  }

  // Group the absentees by the shape the renderer rolls up on, so the disclosed count can be
  // compared with the real one. A shape with absentees but no group block is a silent drop.
  const byShape = new Map<string, Finding[]>();
  for (const f of absent) byShape.set(shapeKey(f), [...(byShape.get(shapeKey(f)) ?? []), f]);

  for (const [shape, group] of byShape) {
    const first = group[0] as Finding;
    const unlisted = group.filter((f) => !rendered(region(f), f.location));
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
