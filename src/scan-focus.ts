// #442 — turn the M3 hotspot ranking into a focus brief for the M1 semantic pass (`/vuln-scan`).
//
// Hot files (high churn × complexity × coupling) are where defects concentrate, so they are the
// highest-yield targets for the paid semantic review — the same signal already steers M8 mutation
// (`mutation-scan --hotspots`) and M6 simplification (`simplify-scan --hotspots`). vuln-scan is an
// operator/skill pass with no CLI seam, so this renders a brief the operator appends to the pass's
// `--extra` inputs: it tells the reviewer to prioritize the hottest files, without dropping the rest.

// Parse the newline-ranked file list M3 emits (`hotspot-scan.ts --hotspots-out`) — one repo-relative
// path per line, hottest first. Blank lines are dropped; order (= rank) is preserved. Shared so both
// LLM passes read the M3 output the same way M8 does.
export function parseHotspots(text: string): string[] {
  return text.split("\n").map((l) => l.trim()).filter(Boolean);
}

// Render the focus brief. Empty input throws: a focus brief with no files is not a focus brief, and
// silently emitting an empty one would let an operator believe the pass was prioritized when it was
// not (the repo's fail-loud rule).
export function buildScanFocus(hotspots: string[]): string {
  if (!hotspots.length) {
    throw new Error("no hotspots to focus on — M3 emitted an empty ranking; run hotspot-scan first, or omit the focus brief");
  }
  const ranked = hotspots.map((path, i) => `${i + 1}. \`${path}\``).join("\n");
  return `## HOTSPOT FOCUS (M3 → M1 semantic pass, #442)

Review the files below FIRST and MOST CAREFULLY. They are this codebase's hotspots — highest churn ×
complexity × coupling — where multi-tenant security defects concentrate. This is a priority ordering,
not a scope limit: still review every file the scan covers, but spend the deepest attention here, and
when triaging, weight a finding in a hotspot file higher (it sits in the most-changed, most-coupled code).

${ranked}
`;
}
