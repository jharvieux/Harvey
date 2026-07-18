// Derives the deliverable's completeness claim from the coverage ledger (#509) — never from
// operator/agent prose. #349 closed the ledger->report path (a never-run module renders as a "Not
// run" row instead of silence); this closes the ledger->HEADLINE path the same way. The ATC
// incident this fixes: the ledger held M2/M3 requires-live-run and M4/M5 partial while the operator
// summary said "the full audit is done" — the ledger was honest, the headline was not.
//
// Two consumers: report-template/render.mjs renders completenessStatement()'s structural banner
// ahead of the free-text headline (a plain-JS mirror of deriveCompleteness, matching the existing
// bftb() duplication between src/findings.ts and render.mjs); findings.ts's validateFindings uses
// headlineClaimsCompletion() as a backstop lint on the free text itself. The banner is the actual
// guarantee — prose can always dodge a regex.

import type { CoverageRow } from "./findings.js";

interface CompletenessVerdict {
  complete: boolean;
  ranCount: number;
  total: number;
  gaps: CoverageRow[]; // non-"ran" rows, ledger order
}

export function deriveCompleteness(rows: CoverageRow[]): CompletenessVerdict {
  const gaps = rows.filter((r) => r.status !== "ran");
  return { complete: gaps.length === 0, ranCount: rows.length - gaps.length, total: rows.length, gaps };
}

// The one sanctioned way to state completeness in prose (report banners, CLI summaries). Never
// hand-write this claim — derive it here from the ledger every time.
export function completenessStatement(rows: CoverageRow[]): string {
  const v = deriveCompleteness(rows);
  if (v.total === 0) return "No coverage ledger — completeness unknown.";
  if (v.complete) return `Full ${v.total}-module audit — all modules assessed.`;
  const gapList = v.gaps.map((g) => `${g.module} (${g.status}${g.reason ? `: ${g.reason}` : ""})`).join("; ");
  return `Partial audit — ${v.ranCount}/${v.total} modules fully assessed. Not fully run: ${gapList}`;
}

// Best-effort textual check for a prose completion claim ("the full audit is done", "audit
// complete") near the words audit/deliverable/engagement/report. Not exhaustive — free text can
// always dodge a regex, which is why the render banner above (not this) is the actual guarantee —
// but it catches the literal phrasing from the ATC incident and is cheap insurance in
// validateFindings.
const COMPLETION_CLAIM =
  /\b(?:audit|deliverable|engagement|report)\b[\w\s]{0,25}\b(?:is|was)\s+(?:fully\s+)?(?:done|complete|finished)\b|\b(?:full|complete|whole)\s+(?:ten[- ]module\s+)?audit\s+(?:is|was)\s+(?:done|complete|rendered|ready)\b/i;

export function headlineClaimsCompletion(headline: string): boolean {
  return COMPLETION_CLAIM.test(headline);
}
