// Audit report renderer — findings.json → hybrid HTML (dashboard cover + formal
// findings body) → PDF, using the repo's Playwright (no new dependency).
//
//   node report-template/render.mjs <findings.json> [outDir]
//
// Emits report.html, report.pdf, and page1.png (QA screenshot) in outDir.
// The findings DATA drives everything — swap the JSON per engagement, format stays.
//
// Schema note (#259): this consumes the PAID full-engagement findings.<client>.json
// (meta + findings[] with confidence/value/ease/safety) — a different, independent
// schema from QuickScanReport (src/quick-scan.ts), the FREE tier's grade/indicators/
// informational shape. quick-scan has no export into this renderer today; don't
// conflate the two when either schema changes.
//
// #1099: healthGauge/severityDonut/completenessBanner/coverageSection/limitationsSection are
// exported (only) so they have a test — see src/report-render.test.ts, same pattern sections.mjs
// already established (report-sections.test.ts) rather than testing them where they were unhomed.
// The bottom of this file (reading argv, launching Chromium) stays a script, not a library.

import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright";
import { capActionPlan, rollupFindings } from "./rollup.mjs";
import { draftTermsBadge, esc, legalTermsSection, notApplicableSection, tenantIsolationPill, testQualityBlock } from "./sections.mjs";

const SEV = {
  Critical: { c: "#b3261e", o: 0 },
  High: { c: "#d9730d", o: 1 },
  Medium: { c: "#b88600", o: 2 },
  Low: { c: "#3b7ea1", o: 3 },
  Perf: { c: "#7c3aed", o: 4 },
  Info: { c: "#64748b", o: 5 },
  Watch: { c: "#475569", o: 6 },
};
const bftb = (f) => Math.round((f.value * f.ease * f.safety) / 125 * 100);
// Priority heat: highest bang-for-the-buck = deep red (fix first), sliding continuously through
// orange to amber as the score drops. Never green — green reads as "all clear", and every BFTB
// row is something to fix. Continuous hue, not discrete buckets.
const bftbColor = (s) => {
  const t = Math.max(0, Math.min(1, s / 100)); // 1 = top priority
  const hue = Math.round(45 - 45 * t);         // 45 (amber) → 0 (red)
  const light = Math.round(47 - 7 * t);        // deepen toward red at the top
  return `hsl(${hue}, 88%, ${light}%)`;
};
const CONF = { Confirmed: "#2563eb", Likely: "#ca8a04", Review: "#facc15", "N/A": "#94a3b8" };
// Pick a legible text color for a badge background (dark ink on light fills like the Review yellow).
const readableOn = (hex) => {
  const n = parseInt(hex.slice(1), 16);
  return (0.299 * (n >> 16 & 255) + 0.587 * (n >> 8 & 255) + 0.114 * (n & 255)) > 150 ? "#1f2937" : "#fff";
};

// SVG arc helper (degrees; 0 = +x axis, sweeps clockwise in screen coords).
const pol = (cx, cy, r, deg) => [cx + r * Math.cos((deg * Math.PI) / 180), cy + r * Math.sin((deg * Math.PI) / 180)];
function arc(cx, cy, r, a0, a1, color, w) {
  const [x0, y0] = pol(cx, cy, r, a0);
  const [x1, y1] = pol(cx, cy, r, a1);
  const large = a1 - a0 > 180 ? 1 : 0;
  return `<path d="M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}" fill="none" stroke="${color}" stroke-width="${w}" stroke-linecap="round"/>`;
}

export function healthGauge(v) {
  const frac = Math.max(0, Math.min(1, v / 10));
  const col = v >= 7 ? "#15803d" : v >= 4 ? "#ca8a04" : "#b3261e";
  return `<svg width="190" height="120" viewBox="0 0 190 120">
    ${arc(95, 100, 72, 180, 360, "#e5e7eb", 14)}
    ${arc(95, 100, 72, 180, 180 + frac * 180, col, 14)}
    <text x="95" y="92" text-anchor="middle" font-size="34" font-weight="800" fill="#0f172a">${v}</text>
    <text x="95" y="112" text-anchor="middle" font-size="12" fill="#64748b">/ 10 health</text>
  </svg>`;
}

export function severityDonut(counts) {
  const entries = Object.entries(counts).filter(([, n]) => n > 0).sort((a, b) => SEV[a[0]].o - SEV[b[0]].o);
  const total = entries.reduce((s, [, n]) => s + n, 0) || 1;
  let a = -90;
  const segs = entries.map(([sev, n]) => {
    const sweep = (n / total) * 360;
    const p = arc(70, 70, 52, a + 1, a + sweep - 1, SEV[sev].c, 16);
    a += sweep;
    return p;
  }).join("");
  return `<svg width="140" height="140" viewBox="0 0 140 140">${segs}
    <text x="70" y="66" text-anchor="middle" font-size="26" font-weight="800" fill="#0f172a">${total}</text>
    <text x="70" y="84" text-anchor="middle" font-size="10" fill="#64748b">findings</text></svg>`;
}

function bftbBars(items) {
  return items.map((f) => {
    const s = bftb(f);
    return `<div class="bar-row"><div class="bar-score" style="color:${bftbColor(s)}">${s}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${s}%;background:${bftbColor(s)}"></div></div>
      <div class="bar-label">${esc(f.title)}</div></div>`;
  }).join("");
}

// CWE/OWASP identifiers (#455) — absent unless the scanner populated them, so a finding with no
// defensible mapping renders exactly as before (no empty "CWE: —" line).
function cweOwaspLine(f) {
  const parts = [
    ...(f.cwe ?? []).map((id) => esc(id)),
    ...(f.owasp ?? []).map((id) => esc(id)),
  ];
  if (parts.length === 0) return "";
  return `<div class="kv"><b>CWE/OWASP</b> ${parts.join(" · ")}</div>`;
}

// #1077: the rule's own remediation links (semgrep metadata.references + its source page) —
// absent unless the source declared any (e.g. every one of Harvey's own harvey-* rules today, which
// carry no references, so the Fix line above stays the generic placeholder for those).
function referencesLine(f) {
  if (!f.references?.length) return "";
  const links = f.references.map((r) => `<a href="${esc(r)}">${esc(r)}</a>`).join(" · ");
  return `<div class="kv"><b>References</b> ${links}</div>`;
}

// #825: the paid-tier applicable diff, in the report the client actually reads.
//
// `Finding.suggestedFix` is written by exactly one place — src/fix/attach.ts — which refuses to
// attach unless the diff verified green AND the engagement is paid AND the finding clears the same
// severity/confidence floor the ticket filer applies. So its presence here IS the gate; this
// renderer re-decides none of it, exactly as ticketBody does not.
//
// Why it exists: #825's diff reached filed tickets (src/trackers/fix-diff.ts renderFixSection) and
// stopped there. The written report is the deliverable a client reads first, and it showed the prose
// `fix` while the verified patch — the thing the paid tier is sold on — was dropped at the render
// seam. That is the producer→consumer gap #825 exists to close, one step further out than the
// ticket body. Rendering mirrors the ticket: the diff under the prose Fix, marked inert, followed by
// what was actually checked (never a bare "verified", which is a claim with no content behind it).
function suggestedFixBlock(f) {
  const sf = f.suggestedFix;
  if (!sf?.verified || !sf.diff.trim()) return "";
  return `<div class="sfix">
    <div class="cu">Suggested fix — inert, for review. Harvey does not apply it.</div>
    <pre class="diff">${esc(sf.diff.replace(/\n+$/, ""))}</pre>
    ${sf.verification ? `<div class="sfv">Mechanically verified: ${esc(sf.verification)}</div>` : ""}
  </div>`;
}

function findingCard(f) {
  const s = bftb(f);
  const sc = SEV[f.severity]?.c ?? "#64748b";
  return `<div class="finding">
    <div class="finding-head">
      <span class="fid">${esc(f.id)}</span>
      <span class="ftitle">${esc(f.title)}</span>
      <span class="badge" style="background:${sc}">${esc(f.severity)}</span>
      <span class="badge bftb" style="background:${bftbColor(s)}">BFTB ${s}</span>
      <span class="badge" style="background:${CONF[f.confidence] ?? "#94a3b8"};color:${readableOn(CONF[f.confidence] ?? "#94a3b8")}">${esc(f.confidence ?? "—")}</span>
      ${baselineBadge(f)}
      ${f.onHotspot ? `<span class="badge" style="background:#7c3aed" title="On an M3 churn×complexity hotspot — higher remediation priority">🔥 Hotspot${f.hotspotRank ? ` #${f.hotspotRank}` : ""}</span>` : ""}
      ${f.dataClass?.escalatedFrom ? `<span class="badge" style="background:#be123c" title="${esc(f.dataClass.reason)}">↑ ${esc(f.dataClass.escalatedFrom)} · ${esc(f.dataClass.categories.join("/"))}</span>` : ""}
    </div>
    <div class="finding-meta">${esc(f.category)} · ${esc(f.taxonomy)} · <code>${esc(f.location)}</code> · <span class="status">${esc(f.status)}</span>
      · <span class="vesc">V${f.value}·E${f.ease}·S${f.safety}</span></div>
    ${cweOwaspLine(f)}
    ${f.dataClass ? `<div class="kv"><b>Data class</b> ${esc(f.dataClass.reason)}</div>` : ""}
    <div class="kv"><b>Evidence</b> ${esc(f.evidence)}</div>
    <div class="kv"><b>Impact</b> ${esc(f.impact)}</div>
    <div class="kv"><b>Fix</b> ${esc(f.fix)}</div>
    ${suggestedFixBlock(f)}
    ${referencesLine(f)}
    ${f.lowConfidenceMatch ? `<div class="crit"><div class="cu">⚠ Possible carry-over — confirm manually:</div>
      <div>This looks like it might be the same issue as prior finding <b>${esc(f.lowConfidenceMatch)}</b>, but the match was not confident (a rename or re-label), so it is counted as <b>new</b> and that prior finding still shows as resolved. Confirm whether they are the same before reporting progress.</div></div>` : ""}
    ${f.okWhen || f.notOkWhen ? `<div class="crit"><div class="cu">When this is OK vs. not — confirm against your design:</div>
      ${f.okWhen ? `<div><span class="ok">✓ OK when</span> ${esc(f.okWhen)}</div>` : ""}
      ${f.notOkWhen ? `<div><span class="notok">✗ Not OK when</span> ${esc(f.notOkWhen)}</div>` : ""}</div>` : ""}
  </div>`;
}

// #935: a rolled-up shape — same taxonomy + severity, more findings than the rollup threshold
// (rollup.mjs). The top members render as full cards; the remainder is disclosed BY COUNT, with
// every withheld location present in a collapsed <details> (the PDF prints its summary line, the
// HTML expands to the full list) and in the machine-readable findings.json/SARIF. The count line
// is the no-silent-cap contract: what is not individually rendered is stated, never absorbed.
function groupCard(g) {
  const sc = SEV[g.severity]?.c ?? "#64748b";
  const withheldLocs = g.withheld
    .map((f) => `<div><span class="fid">${esc(f.id)}</span> <code>${esc(f.location)}</code></div>`)
    .join("");
  return `<div class="group">
    <div class="group-head">
      <span class="badge" style="background:${sc}">${esc(g.severity)}</span>
      <span class="group-title">${esc(g.taxonomy)}</span>
      <span class="group-count">${g.count} findings of this shape — top ${g.representatives.length} shown in full</span>
    </div>
    ${g.representatives.map(findingCard).join("")}
    <div class="group-rest">
      <b>${g.withheld.length} more ${esc(g.severity)} finding(s) of this shape are not individually rendered.</b>
      Every one is in the machine-readable findings.json (and the SARIF export when produced) with its
      full evidence and fix; locations below.
      <details><summary>All ${g.withheld.length} withheld locations</summary>${withheldLocs}</details>
    </div>
  </div>`;
}

// Engagement baseline diff (#457). A per-finding badge showing its standing vs the prior audit:
// "new" this quarter, or "carried over" (persistent). Absent baselineStatus (no baseline supplied)
// ⇒ no badge, so a first-time engagement renders exactly as before.
const BASELINE_BADGE = {
  new: { label: "NEW", c: "#fff", bg: "#b3261e" },
  persistent: { label: "CARRIED OVER", c: "#334155", bg: "#e2e8f0" },
};
function baselineBadge(f) {
  const b = BASELINE_BADGE[f.baselineStatus];
  return b ? `<span class="badge" style="background:${b.bg};color:${b.c}">${b.label}</span>` : "";
}

// The progress banner — the client-facing lead when a re-audit consumed a baseline (#457). Resolved
// is the good number and leads; new is the number to act on. A resolved count with no persistent/new
// still renders, because "you closed everything" is the strongest possible progress statement.
function baselineBanner(baseline) {
  const { resolved, persistent, new: added } = baseline.counts;
  const since = baseline.priorLabel ? ` since the prior audit (${esc(baseline.priorLabel)})` : " since the prior audit";
  return `<div class="progress">
    <div class="progress-title">Progress${since}</div>
    <div class="progress-stats">
      <div class="pstat"><div class="pnum" style="color:#15803d">${resolved}</div><div class="plabel">Resolved</div></div>
      <div class="pstat"><div class="pnum" style="color:#334155">${persistent}</div><div class="plabel">Still open</div></div>
      <div class="pstat"><div class="pnum" style="color:#b3261e">${added}</div><div class="plabel">New</div></div>
    </div>
  </div>`;
}

// Resolved findings — closed since the prior audit. Listed so the client sees exactly what improved,
// not just a count. These come from the baseline, not the current run, and are not in the findings
// body above.
function resolvedSection(resolved) {
  const rows = resolved.map((x) => `<div class="na"><span class="fid" style="color:#15803d">✓ ${esc(x.id)}</span> <b>${esc(x.title)}</b> — <span style="color:var(--muted)">${esc(x.category)} · ${esc(x.taxonomy)} · <code>${esc(x.location)}</code></span></div>`).join("");
  return `<h2>Resolved since last audit</h2>
    <div style="font-size:11px;color:var(--muted);margin-bottom:8px">Findings from the prior audit that are absent from this run — matched by finding identity (rule/taxonomy + normalized location), robust to line-number churn.</div>
    ${rows}`;
}

// Per-module coverage badge palette (#349). "Not assessed" is deliberately alarming: a module that
// never ran contributes no findings, and without this row that silence reads as "clean".
const COV = {
  ran: { label: "Assessed", c: "#15803d", bg: "#f0fdf4", bd: "#bbf7d0" },
  partial: { label: "Partial", c: "#b88600", bg: "#fffbeb", bd: "#fde68a" },
  "requires-live-run": { label: "Not assessed", c: "#b3261e", bg: "#fef2f2", bd: "#fecaca" },
};

// The report's completeness claim, derived from the coverage ledger — never from the operator's
// free-text meta.headline (#509). Mirrors src/audit-completeness.ts's deriveCompleteness (same
// duplication pattern as bftb() above: render.mjs is plain JS, not built from src/*.ts). Renders
// ahead of meta.headline so a "the audit is done" headline can never talk over a ledger that
// disagrees — the ATC incident this closes. No ledger (hand-authored legacy doc) ⇒ no banner.
export function completenessBanner(rows) {
  if (!rows?.length) return "";
  const gaps = rows.filter((r) => r.status !== "ran");
  if (!gaps.length) {
    return `<div class="headline"><b>Full ${rows.length}-module audit</b> — all modules assessed.</div>`;
  }
  const gapList = gaps.map((g) => `${esc(g.module)} (${esc(g.status)})`).join(", ");
  return `<div class="headline" style="background:#fef2f2;border-color:#fecaca">
    <b style="color:#b3261e">Partial audit — ${rows.length - gaps.length}/${rows.length} modules fully assessed.</b>
    Not fully run: ${gapList}. See Module coverage below for reasons.</div>`;
}

// The derived coverage ledger, rendered as the report's authoritative coverage statement (#349).
// Replaces the hand-typed meta.outOfScope as the source of truth; outOfScope is demoted to a note.
export function coverageSection(rows, m) {
  const body = rows.map((r) => {
    // #682: a partial whose status is a BLOCKED sub-step (its sibling sub-step still ran and
    // surfaced findings) is badged distinctly from an ordinary partial — the reader must be able to
    // tell "we ran part of this and here's what we found" from "produced nothing".
    const blocked = r.status === "partial" && r.subStatus === "sub-step-blocked";
    const s = blocked
      ? { label: "Partial — sub-step blocked", c: "#b88600", bg: "#fffbeb", bd: "#fde68a" }
      : COV[r.status] ?? COV["requires-live-run"];
    // #1555: the column header promises "What ran / why not", and this branch used to deliver only
    // ONE of them — `detail` on a `ran` row, `reason` otherwise. So a `partial` row's `detail`, which
    // is what the module DID run, never reached the client. That silently dropped the #502 warning
    // ("no M3 hotspot focus — the semantic pass was NOT hotspot-prioritized") the moment #1553 made
    // M1 correctly read `partial` in a realistic engagement: still in findings.json, gone from the
    // report a person reads. Render both — detail first (what ran), then the reason it fell short —
    // rather than merging them, because they answer different questions and a reader must be able to
    // tell "we ran the mechanical tier but not the semantic one" from "we ran nothing".
    const note = [r.detail, r.reason].filter((t) => t && t.trim()).map(esc).join("<br>");
    // #506: a per-app/per-DB row names its instance so a monorepo's second app/DB is a visible row,
    // never folded into the module's headline.
    const area = r.instance ? `${esc(r.name)} <span style="color:var(--muted)">· ${esc(r.instance)}</span>` : esc(r.name);
    return `<tr><td class="b">${esc(r.module)}</td><td>${area}</td>
      <td><span class="cov-badge" style="color:${s.c};background:${s.bg};border:1px solid ${s.bd}">${s.label}</span></td>
      <td>${note}</td></tr>`;
  }).join("");
  const notAssessed = rows.filter((r) => r.status === "requires-live-run").length;
  const intro = notAssessed
    ? `A module marked <b style="color:#b3261e">Not assessed</b> produced no findings because it did not run — <b>this is not a clean result</b>; the reason is stated.`
    : "Every module was assessed.";
  return `<h2>Module coverage</h2>
    <div style="font-size:11px;color:var(--muted);margin-bottom:6px">All ten audit modules, and whether each was assessed on this engagement. ${intro}</div>
    <table class="cov"><tr><th>Module</th><th>Area</th><th>Status</th><th>What ran / why not</th></tr>${body}</table>
    <div class="kv" style="margin-top:10px"><b>Out of scope</b> ${esc(m.outOfScope)}</div>`;
}

// Per-module confidence & known limitations (#822). Competitors sell on a transparent-limitations
// story; before this, Harvey's hedges (unverified advisor path, lab-not-field CWV, packet-not-
// verdict, mechanical-tier precision) lived scattered across code comments/docs, invisible to the
// client. These are properties of the METHOD itself — not derived from what fired this engagement
// — so the table is static and renders one line per module regardless of findings. Keyed by module
// id to match audit-coverage.ts's AUDIT_MODULES / the coverage ledger's r.module (same manual-sync
// mirroring note as coverageSection above: render.mjs is plain JS, not built from src/*.ts).
const MODULE_LIMITATIONS = {
  M1: { name: "Multi-tenant security", note: "Mechanical/config detectors are pattern-based against a calibration corpus, not exhaustive. LLM semantic findings carry a Confidence tag (Likely/Review) until manually confirmed. Live RLS/policy review needs connected-tier DB access." },
  M2: { name: "Local pen-test (dynamic)", note: "Proves isolation against a freshly seeded local stack with synthetic tenants — confirms the app as configured, not production data or config drift since deploy." },
  M3: { name: "Hotspot analysis", note: "Churn × complexity ranking depends on git history depth; a shallow clone or young repo yields a thin signal." },
  M4: { name: "Duplication", note: "Mechanical clone detection; some duplication may be intentional (generated code, fixtures) — reviewed, not auto-excluded." },
  M5: { name: "Slop / dead code", note: "Flags candidate unused exports/code mechanically; some may be public API or dynamically referenced — review before pruning." },
  M6: { name: "Simplification / maintainability", note: "The free tier is non-grading indicators only. The paid verdict is a reviewed judgment over a packet — an unreviewed packet is not a verdict." },
  // #1279's code-tier precision hedge. The number is a FIELD number and must stay one: it comes
  // from #1261's row-by-row triage of the pinned external corpus against source, NOT from
  // `validate-precision.ts`, whose 100.0% is scored over fixtures this repo authored (one planted
  // instance per class, one lookalike per catalogued FP shape) and is therefore a statement about
  // the corpus, not about the scanner. Do not "update" this to the labeled-corpus figure.
  // MEASURED 2026-07-28 — `pnpm exec tsx src/cli/static-detect.ts <clone>` at each pinned commit,
  // every graded row then read against its own source; method and per-class splits are recorded
  // in src/scan/external-corpus.ts's M7 notes. Re-measure and re-date this sentence whenever an
  // M7 code-tier detector or guard changes.
  //
  // RE-MEASURED 2026-07-28 after #1475-#1480, which fixed six of the false-positive families that
  // 72% was made of. Same six clones, same pins, same rubric, one variable (that change set): 15
  // of the 18 rows the triage graded false no longer emit, and a pristine-main control worktree
  // reprints the original 65 exactly. The number below is therefore a BEFORE/AFTER on identical
  // inputs, not a re-grading — deliberately, because re-scoring the surviving rows under a fresh
  // reading would make the delta unreadable. Two caveats travel with it and belong in the next
  // re-measure, not in this sentence: the residual is a SMALL denominator (50 rows), and the
  // nested-loop-join class is the one place this executor's own reading disagreed with the
  // recorded triage in the FP direction (#1488) — so read 96% as "the six named families are
  // fixed", never as the scanner's settled precision.
  //
  // SETTLED 2026-07-30 (#1488): a third, independent read of the class's 7 field rows against
  // source agrees with the STRICTER prior reading, 5 of 7 false, not #1261's original 2 of 7 —
  // proposit's multi-select.tsx:82 (a UI selection array, bounded by what a user clicked), boxyhq's
  // products.ts:49 and mvp-boilerplate's stripe.ts:151 (both a small fixed Stripe pricing catalog,
  // not tenant data), and saas-lite's is-route-active.ts:96 + app-breadcrumbs.tsx:65 (both
  // collections are URL path segments, bounded by URL depth). Only proposit's members-tab.tsx:77
  // and proposals-server.ts:82 hold — both collections there scale with real org/proposal data.
  // No guard changed — src/detectors/perf-code.ts's #1488 comment on detectNestedLoopJoin records
  // why: the false rows' shape (a parameter-typed array with no local trace to its own origin) is
  // also the shape an existing corpus positive relies on to fire, so a guard broad enough to
  // silence the false rows would silence a real one too. This is therefore a RE-GRADING of the
  // same emitted rows, unlike the 72%->96% before/after above: 3 rows move from held to false in
  // the 50-row residual, 45/50 (90%), not 48/50 (96%).
  //
  // RE-CHECKED 2026-07-31 (#1479's ghostfolio residual) and DELIBERATELY NOT MOVED. Two of the six
  // clones the 90% is drawn from were re-scanned at their pins — carbon reprints 536/718 and
  // ghostfolio 78/78, both byte-identical to the recorded baselines — and the only change that
  // session was to corpus NOTES, not to a detector, so no graded row moved in either direction.
  // Recorded because "re-measure the hedge" has to have a visible negative outcome too: a
  // re-measurement that found no movement is a different fact from one that was never run.
  M7: { name: "Performance", note: "Code-tier findings are AST pattern matches and a share of them do not survive review. Read against source on six pinned open-source codebases: 47 of 65 graded findings held (2026-07-28, 72%); after six named false-positive families were fixed, 45 of the 50 findings that still emit hold (2026-07-30, 90%) — a residual of only 50 rows. One class, nested-loop join, carried a recorded disagreement about its true rate (2 vs. 5 of its 7 field rows false); a third independent read settled it at 5 false, and this figure reflects that reading. A 40-row random sample drawn from 858 graded findings on four larger codebases held 78% before those fixes and has not been re-sampled since. Treat the code-tier list as a strong lead list that still needs reading, not as a verified defect list. Per-class precision is NOT stated for classes with too few field instances to measure — an unquoted class is unmeasured, not clean. Info-severity notes (hook dependencies, and since 2026-07-28 the state-sprawl maintainability observation) are excluded from these counts and are not graded. DB advisor findings reflect the platform's own heuristics, not independently re-verified. Core Web Vitals/Lighthouse figures are a single LAB run, not field/real-user data." },
  M8: { name: "Test quality", note: "A mutation score is only as good as its stated scope — a scoped run is not a whole-repo coverage claim (see Test quality below when present)." },
  M9: { name: "App Router boundary/rendering", note: "AST pattern coverage of App Router conventions, not full framework-semantics execution." },
  M10: { name: "Data classification (PII/PHI/PCI)", note: "Classification is derived from column/schema naming and structure. A JSON/JSONB container is flagged for review, not asserted, and its actual contents are not read." },
};

// Rendered alongside (never instead of) the coverage ledger — coverage says whether a module ran
// this engagement; this says what its result proves and doesn't, independent of that. Same gate as
// coverageSection (no ledger ⇒ no section) so the two never appear out of sync.
export function limitationsSection(rows) {
  const present = new Set(rows.map((r) => r.module));
  const body = Object.entries(MODULE_LIMITATIONS)
    .filter(([id]) => present.has(id))
    .map(([id, mod]) => `<tr><td class="b">${esc(id)}</td><td>${esc(mod.name)}</td><td>${esc(mod.note)}</td></tr>`)
    .join("");
  return `<h2>Confidence &amp; limitations</h2>
    <div style="font-size:11px;color:var(--muted);margin-bottom:6px">What each module's result does and does not prove — independent of whether it ran this engagement (see Module coverage above for that).</div>
    <table class="cov"><tr><th>Module</th><th>Area</th><th>Known limitations</th></tr>${body}</table>`;
}

// #459: M10's OPAQUE_JSON_BLOB review flags (#377) are a "look inside this container" prompt, not
// an asserted PII holding. A reviewFlagOnly finding is excluded from the asserted findings list
// (and from severity/BFTB/action-plan tallies, same treatment as N/A) and rendered here instead;
// a finding that ALSO has asserted columns stays in the asserted list but still lists its flagged
// columns here, so no review-flag content is silently dropped from the report.
function reviewFlagSection(items) {
  const rows = items.map((x) => `<tr><td class="b">${esc(x.location)}</td>
    <td>${x.reviewFlagColumns.map(esc).join(", ")}</td>
    <td>${x.reviewFlagOnly ? "No" : "Yes — see Findings"}</td></tr>`).join("");
  return `<h2>Review for nested PII</h2>
    <div style="font-size:11px;color:var(--muted);margin-bottom:8px">JSON/JSONB container column(s) whose name suggests they may hold nested PII (#377) — flagged for review, not asserted as classified PII, and excluded from the severity counts and action plan.</div>
    <table class="cov"><tr><th>Table</th><th>Column(s) to review</th><th>Also holds asserted PII?</th></tr>${rows}</table>`;
}

// Fix delivery section (#926, design §1.5). Renders the client-handoff artifact
// (src/fix/handoff.ts assembleHandoff → fix-handoff.json, folded into findings.<client>.json as
// data.fixHandoff): two tables — the PRs/fixes being delivered with their verification status and
// recommended merge order, and the "why not automated" downgrades — plus the merge-order advisory.
// Optional: renders only when a fixHandoff is present, so existing engagements are unaffected. A
// downgraded/blocked fix is a ROW WITH A REASON, never omitted (silent omission reads as "handled").
const FIX_STATUS = {
  "pr-opened": { label: "PR opened (draft)", c: "#15803d", bg: "#f0fdf4", bd: "#bbf7d0" },
  "verified-inert": { label: "Verified — pending transport", c: "#2563eb", bg: "#eff6ff", bd: "#bfdbfe" },
  "awaiting-implementer": { label: "Awaiting implementer", c: "#b88600", bg: "#fffbeb", bd: "#fde68a" },
  manual: { label: "Manual (operator)", c: "#b88600", bg: "#fffbeb", bd: "#fde68a" },
  "recommend-only": { label: "Recommend only", c: "#7c3aed", bg: "#f5f3ff", bd: "#ddd6fe" },
  "rails-blocked": { label: "Blocked by rails", c: "#b3261e", bg: "#fef2f2", bd: "#fecaca" },
  "verify-failed": { label: "Verification failed", c: "#b3261e", bg: "#fef2f2", bd: "#fecaca" },
  aborted: { label: "Aborted", c: "#b3261e", bg: "#fef2f2", bd: "#fecaca" },
  "not-approved": { label: "Not approved", c: "#64748b", bg: "#f8fafc", bd: "#e5e7eb" },
};
const DELIVERABLE_FIX = new Set(["pr-opened", "verified-inert", "awaiting-implementer"]);
function fixBadge(status) {
  const s = FIX_STATUS[status] ?? FIX_STATUS["not-approved"];
  return `<span class="cov-badge" style="color:${s.c};background:${s.bg};border:1px solid ${s.bd}">${s.label}</span>`;
}
function fixSection(h) {
  const rows = h.rows ?? [];
  if (!rows.length) return "";
  const delivered = rows.filter((r) => DELIVERABLE_FIX.has(r.status)).sort((a, b) => (a.mergeRank ?? 99) - (b.mergeRank ?? 99));
  const downgraded = rows.filter((r) => !DELIVERABLE_FIX.has(r.status));
  const prCell = (r) => (r.prUrl ? `<a href="${esc(r.prUrl)}">${esc(r.prUrl)}</a>` : "—");
  const deliveredTable = delivered.length
    ? `<table class="cov"><tr><th>Merge #</th><th>Finding</th><th>Status</th><th>PR</th><th>Verification</th></tr>${delivered
        .map((r) => `<tr><td class="b">${r.mergeRank ?? "—"}</td><td class="b">${esc(r.findingId)}</td><td>${fixBadge(r.status)}</td><td>${prCell(r)}</td><td>${esc(r.verification ?? "—")}</td></tr>`)
        .join("")}</table>`
    : `<div class="kv">No automated fixes delivered this engagement.</div>`;
  const notesBlock = h.mergeOrder?.notes?.length
    ? `<div class="kv" style="margin-top:8px"><b>Merge order</b> ${h.mergeOrder.notes.map((n) => esc(n)).join("<br>")}</div>`
    : "";
  const downgradeTable = downgraded.length
    ? `<h2>Recommended fixes (why not automated)</h2>
      <div style="font-size:11px;color:var(--muted);margin-bottom:6px">Approved findings that did NOT become an automated PR — downgraded, blocked, or awaiting review. Each is listed with its reason; none is silently dropped.</div>
      <table class="cov"><tr><th>Finding</th><th>Status</th><th>Reason</th></tr>${downgraded
        .map((r) => `<tr><td class="b">${esc(r.findingId)}</td><td>${fixBadge(r.status)}</td><td>${esc(r.reason ?? "—")}</td></tr>`)
        .join("")}</table>`
    : "";
  return `<h2>Fix delivery</h2>
    <div style="font-size:11px;color:var(--muted);margin-bottom:6px">Fixes prepared for <b>${esc(h.client)}</b> at <code>${esc(h.baselineCommit)}</code>. Every PR stays a draft until the operator flips it; <b>the client merges — Harvey never merges</b>. Follow the merge order where two PRs touch the same file.</div>
    ${deliveredTable}
    ${notesBlock}
    ${downgradeTable}`;
}

export function buildHtml(data) {
  const all = data.findings.map((x) => ({ ...x, _bftb: bftb(x) }));
  const f = all.filter((x) => x.confidence !== "N/A" && !x.reviewFlagOnly); // live findings
  const na = all.filter((x) => x.confidence === "N/A"); // checked & ruled out (applicability gate)
  const reviewFlagged = all.filter((x) => (x.reviewFlagColumns?.length ?? 0) > 0); // #459
  const counts = {};
  for (const x of f) counts[x.severity] = (counts[x.severity] || 0) + 1;
  const sevCount = (s) => f.filter((x) => x.severity === s).length;
  const top = [...f].sort((a, b) => b._bftb - a._bftb).slice(0, 6);
  // #515: a finding on an M3 hotspot is up-ranked among its severity peers — a Critical still leads a
  // hotspot Info, but within a band the hotspot one comes first (it sits in the churny, complex,
  // most-coupled code). onHotspot is a secondary key after severity, ahead of the BFTB tiebreak.
  const hot = (x) => (x.onHotspot ? 1 : 0);
  const actionAll = [...f]
    .filter((x) => (x._bftb > 75 || ["Critical", "High"].includes(x.severity)) && !/^Completed/.test(x.status))
    .sort((a, b) => (sevRank(b) - sevRank(a)) || (hot(b) - hot(a)) || (b._bftb - a._bftb));
  // #935: the action plan caps with a DISCLOSED remainder — at carbon-scale volume an unbounded
  // Critical/High table stops being a plan, but a silently truncated one is worse.
  const { shown: action, withheldCount: actionWithheld } = capActionPlan(actionAll);
  // Findings lead with the most critical (severity desc), then hotspot, then BFTB as the tiebreak.
  const sorted = [...f].sort((a, b) => (sevRank(b) - sevRank(a)) || (hot(b) - hot(a)) || (b._bftb - a._bftb));
  // #935: same-shape volume rolls up for presentation; every finding stays in the data.
  const findingItems = rollupFindings(sorted);
  const rolledUp = findingItems.filter((x) => x.kind === "group");

  const legend = Object.entries(counts).sort((a, b) => SEV[a[0]].o - SEV[b[0]].o)
    .map(([s, n]) => `<span class="leg"><i style="background:${SEV[s].c}"></i>${s} ${n}</span>`).join("");

  const m = data.meta;
  return `<!doctype html><html><head><meta charset="utf-8"><style>
  :root{--ink:#0f172a;--muted:#64748b;--line:#e5e7eb;--accent:#2563eb}
  *{box-sizing:border-box}
  body{margin:0;font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--ink);font-size:12px;line-height:1.5}
  .page{padding:48px 54px}
  .cover-band{height:8px;background:linear-gradient(90deg,#0f172a,#2563eb)}
  h1{font-size:30px;letter-spacing:.5px;margin:0 0 2px}
  .sub{color:var(--muted);font-size:13px;margin-bottom:2px}
  .conf{display:inline-block;margin-top:10px;font-size:10px;letter-spacing:2px;color:#b3261e;border:1px solid #b3261e;border-radius:3px;padding:2px 8px;font-weight:700}
  .grid{display:flex;gap:24px;margin-top:26px;align-items:center}
  .card{border:1px solid var(--line);border-radius:10px;padding:16px 18px}
  .headline{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:14px 18px;margin-top:22px;font-size:13px}
  .headline b{color:#15803d}
  .pill{display:inline-block;background:#dcfce7;color:#15803d;border-radius:999px;padding:2px 10px;font-weight:700;font-size:11px}
  .pill-unverified{background:#fef2f2;color:#b3261e;font-size:10px;white-space:normal}
  .legend{display:flex;gap:14px;flex-wrap:wrap;margin-top:8px;color:var(--muted);font-size:11px}
  .leg i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:middle}
  h2{font-size:15px;margin:26px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--ink);letter-spacing:.3px}
  .bar-row{display:grid;grid-template-columns:34px 90px 1fr;gap:10px;align-items:center;margin:7px 0}
  .bar-score{font-weight:800;text-align:right}
  .bar-track{background:#f1f5f9;border-radius:5px;height:12px;overflow:hidden}
  .bar-fill{height:100%;border-radius:5px}
  .bar-label{font-size:11.5px}
  table{width:100%;border-collapse:collapse;margin-top:6px}
  th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);font-size:11.5px;vertical-align:top}
  th{background:#f8fafc;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px}
  .action th{background:#0f172a;color:#fff}
  .b{font-weight:800}
  .findings{page-break-before:always}
  .finding{border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;padding:12px 14px;margin:12px 0;page-break-inside:avoid}
  .finding-head{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
  .fid{font-weight:800;color:var(--accent)}
  .ftitle{font-weight:700;font-size:13px;flex:1;min-width:240px}
  .badge{color:#fff;border-radius:5px;padding:2px 9px;font-size:10px;font-weight:700;letter-spacing:.3px}
  .badge.bftb{}
  .finding-meta{color:var(--muted);font-size:10.5px;margin:7px 0 9px}
  .finding-meta code{background:#f1f5f9;border-radius:4px;padding:1px 5px}
  .status{font-weight:700;color:#334155}
  .vesc{font-variant-numeric:tabular-nums}
  .kv{margin:4px 0;font-size:11.5px}.kv b{display:inline-block;width:64px;color:var(--muted);font-weight:700}
  .cat{font-size:13px;font-weight:800;margin:18px 0 2px;color:#0f172a}
  .na{border-left:3px solid #cbd5e1;background:#f8fafc;border-radius:6px;padding:8px 12px;margin:7px 0;font-size:11px;color:#475569}
  .na .fid{color:#64748b}
  .crit{background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:8px 10px;margin:7px 0 2px;font-size:11px}
  .crit .cu{color:#92400e;font-weight:700;margin-bottom:4px}
  .crit .ok{color:#15803d;font-weight:700}.crit .notok{color:#b3261e;font-weight:700}
  .sfix{background:#f0f9ff;border:1px solid #bae6fd;border-radius:6px;padding:8px 10px;margin:7px 0 2px}
  .sfix .cu{color:#075985;font-weight:700;font-size:11px;margin-bottom:5px}
  .sfix .diff{background:#0f172a;color:#e2e8f0;border-radius:5px;padding:8px 10px;margin:0;font-size:10px;line-height:1.45;white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere}
  .sfix .sfv{color:#475569;font-size:10.5px;font-style:italic;margin-top:5px}
  .group{border:1px solid var(--line);border-left:4px solid #64748b;border-radius:8px;padding:10px 12px;margin:14px 0}
  .group-head{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-bottom:4px}
  .group-title{font-weight:800;font-size:13px}
  .group-count{font-size:11px;color:var(--muted)}
  .group .finding{margin:10px 0}
  .group-rest{background:#f8fafc;border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:11px;color:#334155}
  .group-rest details{margin-top:6px}
  .group-rest summary{cursor:pointer;font-weight:700}
  .group-rest code{background:#f1f5f9;border-radius:4px;padding:1px 5px}
  .cov-badge{border-radius:5px;padding:1px 8px;font-size:10px;font-weight:700;letter-spacing:.3px;white-space:nowrap}
  table.cov td:first-child{white-space:nowrap;font-weight:800}
  .tq{display:flex;gap:16px;align-items:center;border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin-top:6px}
  .tq-score{font-size:30px;font-weight:800;color:#0f172a;white-space:nowrap}
  .tq-unit{font-size:12px;font-weight:700;color:var(--muted);margin-left:3px}
  .tq-body code{background:#f1f5f9;border-radius:4px;padding:1px 5px}
  .progress{display:flex;align-items:center;gap:28px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:14px 20px;margin-top:14px}
  .progress-title{font-size:12px;font-weight:800;color:#15803d;text-transform:uppercase;letter-spacing:.5px}
  .progress-stats{display:flex;gap:26px}
  .pstat{text-align:center}
  .pnum{font-size:26px;font-weight:800;line-height:1}
  .plabel{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:2px}
  </style></head><body>
  <div class="cover-band"></div>
  <div class="page">
    <h1>Security &amp; Health Audit</h1>
    <div class="sub">${esc(m.client)} — ${esc(m.subtitle)}</div>
    <div class="sub">${esc(m.date)} · ${esc(m.commit)} · Prepared by ${esc(m.auditor)}</div>
    ${m.confidential ? '<div class="conf">CONFIDENTIAL</div>' : ""}${draftTermsBadge(data)}

    <div class="grid">
      <div class="card">${healthGauge(m.overallHealth)}</div>
      <div class="card" style="text-align:center">${severityDonut(counts)}<div class="legend" style="justify-content:center">${legend}</div></div>
      <div class="card" style="flex:1">
        <div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px">Tenant isolation</div>
        <div style="font-size:22px;font-weight:800;margin:4px 0 10px">${esc(m.tenantIsolation)} ${tenantIsolationPill(data.coverage)}</div>
        <div style="display:flex;gap:10px">
          ${["Critical", "High", "Medium", "Low"].map((s) => `<div style="text-align:center"><div style="font-size:22px;font-weight:800;color:${SEV[s].c}">${sevCount(s)}</div><div style="font-size:10px;color:var(--muted)">${s}</div></div>`).join("")}
        </div>
      </div>
    </div>

    ${completenessBanner(data.coverage)}
    <div class="headline">${esc(m.headline)}</div>

    ${data.baseline ? baselineBanner(data.baseline) : ""}

    <h2>Top bang-for-the-buck</h2>
    ${bftbBars(top)}

    <h2>Action plan</h2>
    <div style="font-size:11px;color:var(--muted);margin-bottom:6px">Everything BFTB &gt; 75, plus every Critical/High security finding. ${action.length === 0 ? "" : ""}</div>
    <table class="action"><tr><th>#</th><th>Action</th><th>Why</th><th>BFTB</th><th>Owner</th></tr>
    ${action.length ? action.map((x, i) => `<tr><td>${i + 1}</td><td class="b">${esc(x.fix)}</td><td>${esc(x.title)} — ${esc(x.severity)}</td><td class="b" style="color:${bftbColor(x._bftb)}">${x._bftb}</td><td>${x.category === "Security" ? "Operator" : "Eng"}</td></tr>`).join("")
      : '<tr><td colspan="5">No critical/high security findings and nothing above BFTB 75.</td></tr>'}
    ${actionWithheld ? `<tr><td colspan="5"><b>+ ${actionWithheld} more qualifying action(s) beyond this table's ${action.length}-row cap</b> — every one appears in the Findings section and in the machine-readable findings.json (#935: a capped table always states what it capped).</td></tr>` : ""}
    </table>
    ${["Critical", "High"].every((s) => sevCount(s) === 0) ? '<div style="margin-top:8px;font-size:11.5px;color:#15803d;font-weight:700">✓ No critical or high security issues found.</div>' : ""}
  </div>

  <div class="page findings">
    <h2>Scope &amp; methodology</h2>
    <div class="kv"><b>Reviewed</b> ${esc(m.scope)}</div>
    <div class="kv"><b>Tooling</b> ${esc(m.methodology)}</div>
    ${data.coverage?.length ? coverageSection(data.coverage, m) : `<div class="kv"><b>Out of scope</b> ${esc(m.outOfScope)}</div>`}
    ${data.coverage?.length ? limitationsSection(data.coverage) : ""}
    ${testQualityBlock(data)}
    <h2>Findings</h2>
    ${rolledUp.length ? `<div style="font-size:11px;color:var(--muted);margin-bottom:8px">High-volume shapes are rolled up (#935): ${rolledUp.length} shape(s) totalling ${rolledUp.reduce((s, g) => s + g.count, 0)} findings render as grouped blocks — top instances in full, the rest disclosed by count with every location listed. Nothing is omitted from the underlying findings.json.</div>` : ""}
    ${findingItems.map((item) => (item.kind === "group" ? groupCard(item) : findingCard(item.finding))).join("")}
    ${data.fixHandoff ? fixSection(data.fixHandoff) : ""}
    ${data.baseline?.resolved?.length ? resolvedSection(data.baseline.resolved) : ""}
    ${reviewFlagged.length ? reviewFlagSection(reviewFlagged) : ""}
    ${notApplicableSection(na)}
    ${legalTermsSection(data)}
  </div>
  </body></html>`;
}

function sevRank(f) {
  return { Critical: 5, High: 4, Medium: 3, Low: 1, Perf: 1, Info: 0, Watch: 0 }[f.severity] ?? 0;
}

// #1099: guarded so `import { healthGauge, ... } from "./render.mjs"` (the test file) doesn't also
// run the CLI (argv parsing, a real Chromium launch) as a side effect of importing the exports.
const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const [, , findingsPath, outDirArg] = process.argv;
  const data = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
  const outDir = outDirArg ?? path.join(path.dirname(findingsPath), "out");
  fs.mkdirSync(outDir, { recursive: true });
  const html = buildHtml(data);
  fs.writeFileSync(path.join(outDir, "report.html"), html);

  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: "networkidle" });
  await page.pdf({
    path: path.join(outDir, "report.pdf"),
    format: "A4",
    printBackground: true,
    margin: { top: "0", bottom: "26px", left: "0", right: "0" },
    displayHeaderFooter: true,
    headerTemplate: "<div></div>",
    footerTemplate: `<div style="width:100%;font-size:8px;color:#94a3b8;padding:0 54px;display:flex;justify-content:space-between"><span>${esc(data.meta.client)} — Confidential</span><span class="pageNumber"></span></div>`,
  });
  await page.setViewportSize({ width: 880, height: 1100 });
  await page.screenshot({ path: path.join(outDir, "page1.png"), clip: { x: 0, y: 0, width: 880, height: 1080 } });
  await browser.close();
  console.log("wrote", path.join(outDir, "report.pdf"));
}
