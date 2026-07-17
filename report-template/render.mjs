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

import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright";

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
const esc = (s) => String(s ?? "").replace(/[&<>]/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[m]);

// SVG arc helper (degrees; 0 = +x axis, sweeps clockwise in screen coords).
const pol = (cx, cy, r, deg) => [cx + r * Math.cos((deg * Math.PI) / 180), cy + r * Math.sin((deg * Math.PI) / 180)];
function arc(cx, cy, r, a0, a1, color, w) {
  const [x0, y0] = pol(cx, cy, r, a0);
  const [x1, y1] = pol(cx, cy, r, a1);
  const large = a1 - a0 > 180 ? 1 : 0;
  return `<path d="M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}" fill="none" stroke="${color}" stroke-width="${w}" stroke-linecap="round"/>`;
}

function healthGauge(v) {
  const frac = Math.max(0, Math.min(1, v / 10));
  const col = v >= 7 ? "#15803d" : v >= 4 ? "#ca8a04" : "#b3261e";
  return `<svg width="190" height="120" viewBox="0 0 190 120">
    ${arc(95, 100, 72, 180, 360, "#e5e7eb", 14)}
    ${arc(95, 100, 72, 180, 180 + frac * 180, col, 14)}
    <text x="95" y="92" text-anchor="middle" font-size="34" font-weight="800" fill="#0f172a">${v}</text>
    <text x="95" y="112" text-anchor="middle" font-size="12" fill="#64748b">/ 10 health</text>
  </svg>`;
}

function severityDonut(counts) {
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
    </div>
    <div class="finding-meta">${esc(f.category)} · ${esc(f.taxonomy)} · <code>${esc(f.location)}</code> · <span class="status">${esc(f.status)}</span>
      · <span class="vesc">V${f.value}·E${f.ease}·S${f.safety}</span></div>
    <div class="kv"><b>Evidence</b> ${esc(f.evidence)}</div>
    <div class="kv"><b>Impact</b> ${esc(f.impact)}</div>
    <div class="kv"><b>Fix</b> ${esc(f.fix)}</div>
    ${f.okWhen || f.notOkWhen ? `<div class="crit"><div class="cu">When this is OK vs. not — confirm against your design:</div>
      ${f.okWhen ? `<div><span class="ok">✓ OK when</span> ${esc(f.okWhen)}</div>` : ""}
      ${f.notOkWhen ? `<div><span class="notok">✗ Not OK when</span> ${esc(f.notOkWhen)}</div>` : ""}</div>` : ""}
  </div>`;
}

// Per-module coverage badge palette (#349). "Not assessed" is deliberately alarming: a module that
// never ran contributes no findings, and without this row that silence reads as "clean".
const COV = {
  ran: { label: "Assessed", c: "#15803d", bg: "#f0fdf4", bd: "#bbf7d0" },
  partial: { label: "Partial", c: "#b88600", bg: "#fffbeb", bd: "#fde68a" },
  "requires-live-run": { label: "Not assessed", c: "#b3261e", bg: "#fef2f2", bd: "#fecaca" },
};

// The derived coverage ledger, rendered as the report's authoritative coverage statement (#349).
// Replaces the hand-typed meta.outOfScope as the source of truth; outOfScope is demoted to a note.
function coverageSection(rows, m) {
  const body = rows.map((r) => {
    const s = COV[r.status] ?? COV["requires-live-run"];
    const note = r.status === "ran" ? esc(r.detail ?? "") : esc(r.reason ?? "");
    return `<tr><td class="b">${esc(r.module)}</td><td>${esc(r.name)}</td>
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

// #319: a mutation score in the DELIVERABLE is never a bare percentage. A high score over a scoped
// `mutate` set ("100% over lib/pdf/launch.ts" on an otherwise-untested repo) reads as a repo-level
// test-quality claim and would be a misrepresentation — the same trust-budget risk as the security
// wedge. So this block renders the score and its covered scope TOGETHER, and states the caveat
// whenever the scope is not the whole repo. Optional: only renders when findings.<client>.json
// carries a `testQuality` object, so existing engagements are unaffected until one is added.
function testQualitySection(tq) {
  const scope = Array.isArray(tq.coveredScope) ? tq.coveredScope : [];
  const scopeText = scope.length ? scope.map((s) => `<code>${esc(s)}</code>`).join(", ") : "(scope not stated)";
  const caveat = tq.wholeRepo
    ? `Measured across the whole repository.`
    : `<b style="color:#b3261e">This score is measured over the file(s) above only — a scoped subset, NOT a whole-repo coverage claim.</b> Untested files do not appear in this number.`;
  return `<h2>Test quality (M8)</h2>
    <div class="tq">
      <div class="tq-score">${esc(String(tq.mutationScore))}<span class="tq-unit">% mutation</span></div>
      <div class="tq-body">
        <div><b>Covered scope</b> ${scopeText}</div>
        <div style="margin-top:4px;font-size:11px;color:var(--muted)">${caveat}</div>
      </div>
    </div>`;
}

function buildHtml(data) {
  const all = data.findings.map((x) => ({ ...x, _bftb: bftb(x) }));
  const f = all.filter((x) => x.confidence !== "N/A"); // live findings
  const na = all.filter((x) => x.confidence === "N/A"); // checked & ruled out (applicability gate)
  const counts = {};
  for (const x of f) counts[x.severity] = (counts[x.severity] || 0) + 1;
  const sevCount = (s) => f.filter((x) => x.severity === s).length;
  const top = [...f].sort((a, b) => b._bftb - a._bftb).slice(0, 6);
  const action = [...f]
    .filter((x) => (x._bftb > 75 || ["Critical", "High"].includes(x.severity)) && !/^Completed/.test(x.status))
    .sort((a, b) => (sevRank(b) - sevRank(a)) || (b._bftb - a._bftb));
  // Findings lead with the most critical (severity desc), BFTB as the tiebreak.
  const sorted = [...f].sort((a, b) => (sevRank(b) - sevRank(a)) || (b._bftb - a._bftb));

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
  .cov-badge{border-radius:5px;padding:1px 8px;font-size:10px;font-weight:700;letter-spacing:.3px;white-space:nowrap}
  table.cov td:first-child{white-space:nowrap;font-weight:800}
  .tq{display:flex;gap:16px;align-items:center;border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin-top:6px}
  .tq-score{font-size:30px;font-weight:800;color:#0f172a;white-space:nowrap}
  .tq-unit{font-size:12px;font-weight:700;color:var(--muted);margin-left:3px}
  .tq-body code{background:#f1f5f9;border-radius:4px;padding:1px 5px}
  </style></head><body>
  <div class="cover-band"></div>
  <div class="page">
    <h1>Security &amp; Health Audit</h1>
    <div class="sub">${esc(m.client)} — ${esc(m.subtitle)}</div>
    <div class="sub">${esc(m.date)} · ${esc(m.commit)} · Prepared by ${esc(m.auditor)}</div>
    ${m.confidential ? '<div class="conf">CONFIDENTIAL</div>' : ""}

    <div class="grid">
      <div class="card">${healthGauge(m.overallHealth)}</div>
      <div class="card" style="text-align:center">${severityDonut(counts)}<div class="legend" style="justify-content:center">${legend}</div></div>
      <div class="card" style="flex:1">
        <div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px">Tenant isolation</div>
        <div style="font-size:22px;font-weight:800;margin:4px 0 10px">${esc(m.tenantIsolation)} <span class="pill">verified</span></div>
        <div style="display:flex;gap:10px">
          ${["Critical", "High", "Medium", "Low"].map((s) => `<div style="text-align:center"><div style="font-size:22px;font-weight:800;color:${SEV[s].c}">${sevCount(s)}</div><div style="font-size:10px;color:var(--muted)">${s}</div></div>`).join("")}
        </div>
      </div>
    </div>

    <div class="headline">${esc(m.headline)}</div>

    <h2>Top bang-for-the-buck</h2>
    ${bftbBars(top)}

    <h2>Action plan</h2>
    <div style="font-size:11px;color:var(--muted);margin-bottom:6px">Everything BFTB &gt; 75, plus every Critical/High security finding. ${action.length === 0 ? "" : ""}</div>
    <table class="action"><tr><th>#</th><th>Action</th><th>Why</th><th>BFTB</th><th>Owner</th></tr>
    ${action.length ? action.map((x, i) => `<tr><td>${i + 1}</td><td class="b">${esc(x.fix)}</td><td>${esc(x.title)} — ${esc(x.severity)}</td><td class="b" style="color:${bftbColor(x._bftb)}">${x._bftb}</td><td>${x.category === "Security" ? "Operator" : "Eng"}</td></tr>`).join("")
      : '<tr><td colspan="5">No critical/high security findings and nothing above BFTB 75.</td></tr>'}
    </table>
    ${["Critical", "High"].every((s) => sevCount(s) === 0) ? '<div style="margin-top:8px;font-size:11.5px;color:#15803d;font-weight:700">✓ No critical or high security issues found.</div>' : ""}
  </div>

  <div class="page findings">
    <h2>Scope &amp; methodology</h2>
    <div class="kv"><b>Reviewed</b> ${esc(m.scope)}</div>
    <div class="kv"><b>Tooling</b> ${esc(m.methodology)}</div>
    ${data.coverage?.length ? coverageSection(data.coverage, m) : `<div class="kv"><b>Out of scope</b> ${esc(m.outOfScope)}</div>`}
    ${data.testQuality ? testQualitySection(data.testQuality) : ""}
    <h2>Findings</h2>
    ${sorted.map(findingCard).join("")}
    ${na.length ? `<h2>Checked &amp; ruled out (not applicable)</h2>
    <div style="font-size:11px;color:var(--muted);margin-bottom:8px">Items a checklist would flag, suppressed by the applicability gate (relevant to this app's auth model / architecture). Shown for transparency.</div>
    ${na.map((x) => `<div class="na"><span class="fid">${esc(x.id)}</span> <b>${esc(x.title)}</b> — ${esc(x.note ?? "Not applicable in context.")}</div>`).join("")}` : ""}
  </div>
  </body></html>`;
}

function sevRank(f) {
  return { Critical: 5, High: 4, Medium: 3, Low: 1, Perf: 1, Info: 0, Watch: 0 }[f.severity] ?? 0;
}

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
