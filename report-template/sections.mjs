// Two client-facing report sections that carry rules worth testing on their own, split out of
// render.mjs so they can be unit-tested without launching Chromium (same pattern, and the same
// reason, as rollup.mjs — see src/report-sections.test.ts).
//
//   1. §3b Test quality & intent (M8)   — #1045
//   2. §0 Limitations & liability        — #1048
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

// ---------------------------------------------------------------------------
// §0 Limitations & liability — #1048
// ---------------------------------------------------------------------------
//
// docs/audit-report-skeleton.md §0 makes this REQUIRED: "point-in-time advisory; not a guarantee of
// completeness; not a substitute for a full penetration test; liability capped at fees paid. (LLC +
// this paragraph = bounded risk.)" The renderer emitted none of it, so every delivered report went
// out with no stated limitations — which reads as an unbounded warranty.
//
// The section is NEVER gated: absent operator/counsel-approved wording it renders the DRAFT below
// under a banner that makes shipping it as-is impossible to do by accident. That is deliberate — a
// report silently missing its terms is the failure this closes, so "no approved text" degrades to a
// loud draft rather than to silence.
//
// DRAFT STATUS: the wording below was drafted by the audit tooling and has NOT been reviewed by
// counsel. It is placeholder scaffolding for the real terms. Harvey #11 (form the LLC + standard
// engagement/liability terms) and #743 (trust pages, legal review) track the approval; when counsel
// signs off, the approved text goes in the findings document as `legalTerms.text` and this constant
// stops rendering.
export const DRAFT_NOTICE = "DRAFT — NOT REVIEWED BY COUNSEL";

// Each entry is one paragraph of the draft. Kept as data so a test can pin that every element the
// skeleton names (point-in-time, no-completeness-guarantee, not-a-pentest, liability cap) is present.
export const DRAFT_TERMS = [
  ["Point-in-time advisory", "This report describes the codebase as it stood at the commit and date on the cover page. It is a point-in-time advisory and says nothing about the state of the code, its configuration, or its dependencies before or after that point. Changes made after the reviewed commit — including changes made in response to this report — are not covered."],
  ["Not a guarantee of completeness", "The findings in this report are the issues this engagement identified within its stated scope. They are not a complete inventory of the defects, vulnerabilities, or risks present in the reviewed code. The absence of a finding is not evidence that a class of issue does not exist; the Module coverage and Confidence & limitations tables state what was assessed, what was not, and what each result does and does not prove."],
  ["Not a penetration test or a certification", "This is a code and configuration audit. It is not a substitute for a full penetration test, a red-team exercise, or a formal security certification or attestation, and it must not be represented as any of those to a customer, auditor, insurer, or regulator."],
  ["No warranty", "The report is provided as-is, without warranty of any kind, express or implied, including any warranty of merchantability, fitness for a particular purpose, or non-infringement. Acting on the recommendations in this report — including applying any suggested fix — remains the client's decision and the client's responsibility, and every change should be reviewed and tested by the client before it reaches production."],
  ["Limitation of liability", "To the maximum extent permitted by law, total liability arising out of or relating to this engagement is limited to the fees actually paid for it, and does not extend to indirect, incidental, consequential, special, or punitive damages, or to lost profits, revenue, or data."],
  ["Confidentiality", "This report is prepared for the named client and contains information about that client's systems. It should be handled as confidential and shared only with people who need it to act on the findings."],
];

// The scope limit sentence is DERIVED from the coverage ledger, not hand-written: the ledger already
// knows exactly which modules did not fully run and why, and a hand-typed scope paragraph would go
// stale the first time a tier was added or dropped.
export function derivedScopeLimits(coverage) {
  const rows = coverage ?? [];
  if (!rows.length) return "This engagement carried no derived coverage ledger, so the modules assessed cannot be enumerated here — treat the scope as unstated rather than complete.";
  const gaps = rows.filter((r) => r.status !== "ran");
  if (!gaps.length) return `All ${rows.length} module row(s) in the coverage ledger were assessed. Scope limits within each module are stated in the Confidence & limitations table.`;
  const list = gaps.map((g) => `${g.module}${g.instance ? ` (${g.instance})` : ""} — ${g.status}: ${g.reason ?? "no reason recorded"}`);
  return `${gaps.length} of ${rows.length} module row(s) were NOT fully assessed on this engagement, and nothing in this report warrants their subject matter: ${list.join("; ")}.`;
}

export function legalTermsSection(data) {
  const m = data.meta ?? {};
  const approved = data.legalTerms?.text;
  const banner = approved
    ? `<div style="font-size:11px;color:var(--muted);margin-bottom:8px">Engagement terms as supplied for this engagement${data.legalTerms.approvedBy ? ` (approved by ${esc(data.legalTerms.approvedBy)})` : " — no approver recorded"}.</div>`
    : `<div class="crit" style="background:#fef2f2;border-color:#fecaca">
        <div class="cu" style="color:#b3261e">⚠ ${DRAFT_NOTICE} — DO NOT DELIVER THIS REPORT AS-IS</div>
        <div>The limitations and liability wording below is <b>placeholder text generated by the audit tooling</b>. It has not been
        reviewed or approved by counsel and is not this engagement's legal terms. Replace it with counsel-approved wording
        (supply <code>legalTerms.text</code> in the findings document) before this report is delivered to a client.
        Tracked by Harvey #11 (entity + standard engagement/liability terms) and #743 (trust pages, legal review).</div>
      </div>`;
  const body = approved
    ? `<div class="kv" style="white-space:pre-wrap">${esc(approved)}</div>`
    : DRAFT_TERMS.map(([h, p]) => `<div class="kv" style="margin-top:8px"><b style="width:auto;display:block;color:#0f172a">${esc(h)}</b>${esc(p)}</div>`).join("");
  return `<h2>Limitations &amp; liability</h2>
    ${banner}
    <div class="kv" style="margin-top:8px"><b style="width:auto;display:block;color:#0f172a">Scope reviewed</b>${esc(m.scope ?? "not stated")}${m.commit ? ` Reviewed at ${esc(m.commit)}${m.date ? ` on ${esc(m.date)}` : ""}.` : ""}</div>
    <div class="kv" style="margin-top:8px"><b style="width:auto;display:block;color:#0f172a">What this engagement did not assess</b>${esc(derivedScopeLimits(data.coverage))}</div>
    ${body}`;
}

// The cover-page counterpart to the banner above: an unapproved report is marked on page one, so a
// draft can never be skimmed past on its way to a client.
export function draftTermsBadge(data) {
  return data.legalTerms?.text ? "" : `<div class="conf" style="margin-left:8px">${DRAFT_NOTICE}</div>`;
}
