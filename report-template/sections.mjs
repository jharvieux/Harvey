// Client-facing report sections that carry rules worth testing on their own, split out of
// render.mjs so they can be unit-tested without launching Chromium (same pattern, and the same
// reason, as rollup.mjs — see src/report-sections.test.ts).
//
//   1. §3b Test quality & intent (M8)   — #1045
// (§0 Limitations & liability follows in #1048.)
//
// Plain .mjs (not src/*.ts) because render.mjs consumes it directly at render time; TS callers get
// types from sections.d.mts.

export const esc = (s) => String(s ?? "").replace(/[&<>]/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[m]);

// ---------------------------------------------------------------------------
// §3b Test quality & intent (M8) — #1045
// ---------------------------------------------------------------------------
//
// Rebuilt to docs/audit-report-skeleton.md §3b, which specifies a PER-MODULE table:
//   | Module / file | Line cov | Mutation score | Surviving mutants (critical) | Action |
// plus the three report-level bullets docs/m8-test-quality.md §5 maps onto this data. The prior
// version drew a single overall score, so a full mutation run's per-module numbers, its line
// coverage, and its surviving-mutant counts had nowhere to land.
//
// Two rules the rebuild keeps from #319/#819, because they are what makes the number honest:
//   - the overall score NEVER prints without its covered scope and the not-whole-repo caveat;
//   - a missing Line-cov cell says WHY it is missing, and is never drawn as 0%.

// Line coverage this far above the mutation score is the module's headline claim: the suite EXECUTES
// the code but does not ASSERT on it. 20 points is the gap at which the two numbers tell different
// stories rather than merely differing (a suite with real assertions typically lands within ~10).
const FALSE_CONFIDENCE_GAP = 20;

function falseConfidence(row) {
  return row.lineCoverage !== undefined && row.lineCoverage - row.mutationScore >= FALSE_CONFIDENCE_GAP;
}

// The §3b Action cell. docs/m8-test-quality.md §5 has the operator write this per row; absent one,
// derive it from the row's own numbers rather than leaving the column blank — a blank Action reads
// as "nothing to do here", which is the opposite of what surviving mutants mean.
export function testQualityAction(row) {
  if (row.action) return row.action;
  const gap = falseConfidence(row)
    ? `False confidence: ${row.lineCoverage}% of lines run but only ${row.mutationScore}% of injected faults are caught. `
    : "";
  if (row.hotspotSurvivingCount > 0) {
    return `${gap}Write denial/boundary tests for the ${row.hotspotSurvivingCount} surviving mutant(s) on flagged M1/M3 hotspot code — highest remediation priority in this module.`;
  }
  if (row.survivingCount > 0) {
    return `${gap}${row.survivingCount} surviving mutant(s): add assertions that fail when the mutated behaviour changes, not just that the code ran.`;
  }
  return `${gap}No surviving mutants — the suite disproved every injected fault in this module.`;
}

function testQualityRows(rows) {
  return rows
    .map((r) => {
      const cov = r.lineCoverage === undefined
        ? '<span style="color:var(--muted)">not generated</span>'
        : `${esc(String(r.lineCoverage))}%`;
      const crit = r.hotspotSurvivingCount > 0
        ? `<b style="color:#b3261e">${r.hotspotSurvivingCount}</b> of ${r.survivingCount}`
        : `${r.hotspotSurvivingCount} of ${r.survivingCount}`;
      const flag = falseConfidence(r)
        ? ' <span class="cov-badge" style="color:#b3261e;background:#fef2f2;border:1px solid #fecaca">False confidence</span>'
        : "";
      return `<tr><td class="b">${esc(r.module)}${flag}</td><td>${cov}</td><td>${esc(String(r.mutationScore))}%</td>
        <td>${crit}</td><td>${esc(testQualityAction(r))}</td></tr>`;
    })
    .join("");
}

function survivorList(tq) {
  if (!tq.survivorTotal) return "";
  const shown = tq.survivors ?? [];
  const rows = shown
    .map((s) => `<tr><td class="b"><code>${esc(s.file)}</code>:${esc(String(s.line))}</td><td>${esc(s.mutator)}</td>
      <td>${s.hotspot ? '<span class="cov-badge" style="color:#7c3aed;background:#f5f3ff;border:1px solid #ddd6fe">Hotspot</span>' : "—"}</td></tr>`)
    .join("");
  const withheld = tq.survivorTotal - shown.length;
  return `<div style="font-size:11px;color:var(--muted);margin:14px 0 4px"><b>Surviving mutants — the tests that can't fail.</b>
      Each row is a change we made to your code that your suite did not notice. Hotspot-flagged ones sit in
      churny, complex, security-relevant code (cross-referenced with M1/M3), so they lead.</div>
    <table class="cov"><tr><th>Location</th><th>Mutator (what changed)</th><th>On hotspot</th></tr>${rows}</table>
    ${withheld > 0 ? `<div style="font-size:11px;color:var(--muted);margin-top:6px"><b>+ ${withheld} more surviving mutant(s)</b> beyond this ${shown.length}-row list — every one is in the machine-readable scan output.</div>` : ""}`;
}

export function testQualitySection(tq) {
  const scope = Array.isArray(tq.coveredScope) ? tq.coveredScope : [];
  const scopeText = scope.length ? scope.map((s) => `<code>${esc(s)}</code>`).join(", ") : "(scope not stated)";
  // #319: a high score over a scoped `mutate` set ("100% over lib/pdf/launch.ts" on an otherwise-
  // untested repo) reads as a repo-level test-quality claim and would be a misrepresentation. The
  // score and its scope render TOGETHER, and an unverified scope is NOT a whole-repo claim.
  const caveat = tq.wholeRepo
    ? "Measured across the whole configured mutate scope."
    : '<b style="color:#b3261e">This score is measured over the file(s) above only — a scoped subset, NOT a whole-repo coverage claim.</b> Untested files do not appear in this number.';
  const rows = Array.isArray(tq.rows) ? tq.rows : [];
  // A run that produced no per-module rows says so — an empty table would read as "no modules to
  // report" rather than "the per-module breakdown was not produced".
  const table = rows.length
    ? `<table class="cov"><tr><th>Module / file</th><th>Line cov</th><th>Mutation score</th><th>Surviving mutants (critical)</th><th>Action</th></tr>${testQualityRows(rows)}</table>`
    : '<div class="kv" style="color:#b3261e"><b>Per-module breakdown not produced by this run</b> — only the overall score above is available.</div>';
  // #819: the Line-cov column is disclosed as ungenerated with its reason, never left to read as 0%.
  const covNote = tq.lineCoverage?.status === "partial"
    ? `<div style="font-size:11px;color:#b3261e;margin-top:6px"><b>Line coverage not generated:</b> ${esc(tq.lineCoverage.reason)} — the Line-cov column is disclosed as ungenerated, not read as 0%.</div>`
    : "";
  return `<h2>Test quality &amp; intent (M8)</h2>
    <div style="font-size:11px;color:var(--muted);margin-bottom:8px">Mutation testing (StrykerJS): <b>your coverage number is lying to you — here's where.</b>
      Line coverage says a line RAN; the mutation score says a fault injected into it would FAIL a test. A module with high
      coverage and a low mutation score has tests that execute the code without asserting on it.</div>
    <div class="tq">
      <div class="tq-score">${esc(String(tq.mutationScore))}<span class="tq-unit">% mutation</span></div>
      <div class="tq-body">
        <div><b>Covered scope</b> ${scopeText}</div>
        <div style="margin-top:4px;font-size:11px;color:var(--muted)">${caveat}</div>
        <div style="margin-top:4px;font-size:11px;color:var(--muted)">${esc(tq.scopeNote ?? "")}</div>
      </div>
    </div>
    ${table}
    ${covNote}
    ${survivorList(tq)}`;
}

// The §3b slot. A run whose mutation tier produced no measurement gets a stated absence, not
// silence: the module ran (or didn't) either way, and an omitted section reads as "nothing to
// report" rather than "this was not measured" — the same failure the coverage ledger exists to stop.
export function testQualityBlock(data) {
  if (data.testQuality) return testQualitySection(data.testQuality);
  const m8 = (data.coverage ?? []).find((r) => r.module === "M8");
  if (!m8) return "";
  const why = m8.status === "ran"
    ? "the module ran but emitted no mutation measurement"
    : `${m8.status} — ${m8.reason ?? "no reason recorded"}`;
  return `<h2>Test quality &amp; intent (M8)</h2>
    <div class="kv" style="color:#b3261e"><b style="width:auto;display:block">No mutation measurement on this engagement</b>
    There is no per-module test-quality table because the mutation tier produced no score: ${esc(why)}.
    This is a stated gap, not a clean result — nothing here says the suite is adequate.</div>`;
}

