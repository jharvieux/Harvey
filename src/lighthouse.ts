// M7 [L] tier (#387) — Core Web Vitals from a real Lighthouse run against a served build of the
// target. This is the only DIRECT user-facing-speed measurement in M7: every other M7 signal
// (code AST, DB advisors, bundle size) is a proxy. Pure transform only — src/cli/lighthouse-scan.ts
// builds+serves the target, drives Chrome via chrome-launcher + the lighthouse Node API, and feeds
// the raw result objects here.
//
// Thresholds are Google's published Core Web Vitals "Good" boundaries
// (https://web.dev/articles/defining-core-web-vitals-thresholds): LCP < 2.5s, CLS < 0.1, and TBT
// < 200ms as Lighthouse's LAB proxy for INP — INP itself is a FIELD-only metric that a Lighthouse
// lab run does not produce, so TBT is what a lab pass can measure against the "< 200ms" intent.
// A single lab run uses simulated throttling and varies run-to-run; these findings measure THIS
// run, not field RUM — the evidence line says so, and a real engagement should corroborate with
// field data or multiple runs.

import type { Finding, Severity } from "./findings.js";
import type { TargetFramework } from "./scan/framework-detect.js";

// An opportunity audit's named offending resource (details.items — #1074). Lighthouse's own shape
// carries many more fields per audit (headings, sortedBy, debugData); only the ones the M7L
// opportunity finding reads are modelled. Verified real (Lighthouse 13.4.0, live capture 2026-07-25,
// unused-css-rules audit — see src/__fixtures__/lighthouse-opportunity-audit.json).
interface LighthouseAuditItem {
  url?: string;
  wastedBytes?: number;
  wastedMs?: number;
}

interface LighthouseAuditDetails {
  type?: string;
  items?: LighthouseAuditItem[];
  overallSavingsMs?: number;
  overallSavingsBytes?: number;
}

interface LighthouseAudit {
  score?: number | null;
  numericValue?: number;
  displayValue?: string;
  // Required on every real LHR audit (node_modules/lighthouse/types/lhr/audit-result.d.ts:57).
  // "error" means the audit failed with no numericValue — a metric in that state was NOT measured
  // and must never be read as passing (#1074). Verified real values (Lighthouse 13.4.0, live
  // capture 2026-07-25): "numeric" (an ordinary measured metric), "metricSavings" (an opportunity
  // audit), "error" (the audit threw — see src/__fixtures__/lighthouse-report-errored.json).
  scoreDisplayMode?: string;
  // Present alongside scoreDisplayMode "error" (verified real, same 2026-07-25 capture).
  errorMessage?: string;
  // The opportunity/remediation layer (#1074) — Lighthouse's ~50 performance audits carry the
  // specific offending resources and a quantified saving here; Harvey previously read only
  // score/numericValue/displayValue for the 3 tracked metrics and dropped this entirely.
  details?: LighthouseAuditDetails;
  metricSavings?: Record<string, number>;
}

// The subset of the Lighthouse result object (LHR) this transform reads. The real object is large;
// only these fields matter for CWV finding shaping.
export interface LighthouseResult {
  finalDisplayedUrl?: string;
  finalUrl?: string;
  requestedUrl?: string;
  categories?: { performance?: { score?: number | null } };
  audits?: Record<string, LighthouseAudit>;
  runtimeError?: { code?: string; message?: string };
  // Non-optional on the real LHR (node_modules/lighthouse/types/lhr/lhr.d.ts:42) — Lighthouse's own
  // caveats about THIS run (redirect, extension interference, throttling disabled, unresponsive
  // page). Optional here only for back-compat with a hand-built LighthouseResult that omits it.
  // Verified real (Lighthouse 13.4.0, 2026-07-25): [] on a clean run, populated with the
  // human-readable warning on a degraded one (e.g. NO_FCP).
  runWarnings?: string[];
}

export interface LighthousePageResult {
  route: string;
  result: LighthouseResult;
}

interface MetricProfile {
  auditId: string;
  label: string;
  // numericValue > goodMax fails Google's "Good"; >= poorMin is the "Poor" bucket (drives severity).
  goodMax: number;
  poorMin: number;
  format: (n: number) => string;
  impact: string;
  fix: string;
  value: number;
  ease: number;
  safety: number;
}

const ms = (n: number): string => `${(n / 1000).toFixed(1)}s`;
const cls = (n: number): string => n.toFixed(3);

const METRICS: MetricProfile[] = [
  {
    auditId: "largest-contentful-paint",
    label: "LCP",
    goodMax: 2500,
    poorMin: 4000,
    format: ms,
    impact:
      "LCP is when the largest content element renders — the user's sense of 'it has loaded'. Above 2.5s reads as slow; above 4s is Poor.",
    fix: "Optimize the LCP element: preload the hero image/font, cut render-blocking JS/CSS, keep the LCP resource out of lazy-loading, and reduce server response time (TTFB).",
    value: 4,
    ease: 2,
    safety: 4,
  },
  {
    auditId: "total-blocking-time",
    label: "TBT",
    goodMax: 200,
    poorMin: 600,
    format: ms,
    impact:
      "TBT sums main-thread blocking during load — Lighthouse's lab proxy for INP/input responsiveness (a lab run cannot measure INP, a field-only metric). High TBT means taps and clicks feel laggy while the page settles.",
    fix: "Break up long JavaScript tasks, defer/code-split non-critical JS, and move heavy work off the main thread — cross-reference the M7B first-load-JS findings for the routes shipping the most script.",
    value: 4,
    ease: 2,
    safety: 4,
  },
  {
    auditId: "cumulative-layout-shift",
    label: "CLS",
    goodMax: 0.1,
    poorMin: 0.25,
    format: cls,
    impact:
      "CLS measures unexpected layout shift during load — content jumping as images, ads, or fonts arrive. Above 0.1 is janky; above 0.25 is Poor.",
    fix: "Reserve space for images/embeds (explicit width/height or aspect-ratio), avoid inserting content above existing content, and use font-display: swap with size-adjust to cut font-swap shift.",
    value: 3,
    ease: 3,
    safety: 4,
  },
];

const PERF_SCORE_GOOD = 0.9;
const PERF_SCORE_POOR = 0.5;
const MAX_LISTED_PAGES = 8;

function pageLabel(page: LighthousePageResult): string {
  return page.route || page.result.finalDisplayedUrl || page.result.finalUrl || page.result.requestedUrl || "/";
}

function pageList(pages: { label: string; text: string }[]): string {
  const shown = pages.slice(0, MAX_LISTED_PAGES);
  const rest = pages.length - shown.length;
  return shown.map((p) => `${p.label} (${p.text})`).join(", ") + (rest > 0 ? `, +${rest} more` : "");
}

// #1074: Lighthouse's own caveats about a run (redirect, extension interference, throttling
// disabled, unresponsive page) for the specific pages a finding is about — appended to that
// finding's evidence rather than discarded, so a "Confirmed" finding doesn't hide a caveat
// Lighthouse itself raised about the same run it was measured from.
function runWarningsNote(pages: LighthousePageResult[], labels: string[]): string {
  const warned = pages.filter((p) => labels.includes(pageLabel(p)) && (p.result.runWarnings?.length ?? 0) > 0);
  if (warned.length === 0) return "";
  const notes = warned.map((p) => `${pageLabel(p)}: ${p.result.runWarnings!.join("; ")}`).join(" | ");
  return ` Lighthouse's own run warnings for this page — ${notes}.`;
}

function metricFinding(profile: MetricProfile, pages: LighthousePageResult[]): Finding | undefined {
  const failing = pages
    .map((p) => ({ label: pageLabel(p), value: p.result.audits?.[profile.auditId]?.numericValue }))
    .filter((p): p is { label: string; value: number } => typeof p.value === "number" && p.value > profile.goodMax)
    .sort((a, b) => b.value - a.value);
  if (failing.length === 0) return undefined;

  const worst = failing[0]!;
  const anyPoor = failing.some((p) => p.value >= profile.poorMin);
  const severity: Severity = anyPoor ? "Perf" : "Low";
  const n = failing.length;

  return {
    id: "M7L-00", // renumbered by parseLighthouseFindings
    status: "Open",
    category: "Performance",
    title: `${n} page${n === 1 ? "" : "s"} with ${profile.label} above Google's "Good" ${profile.format(profile.goodMax)} (worst: ${profile.format(worst.value)})`,
    severity,
    confidence: "Confirmed", // measured from the run — see evidence for the lab-vs-field caveat
    taxonomy: `M7 — ${profile.label} over Core Web Vitals "Good" threshold`,
    location: worst.label,
    evidence:
      `Lighthouse lab ${profile.label}, worst-first: ` +
      pageList(failing.map((p) => ({ label: p.label, text: profile.format(p.value) }))) +
      `. Measured this run under simulated throttling — corroborate with field RUM or repeat runs before acting.` +
      runWarningsNote(pages, failing.map((p) => p.label)),
    impact: profile.impact,
    fix: profile.fix,
    value: profile.value,
    ease: profile.ease,
    safety: profile.safety,
  };
}

// #1074: an audit whose scoreDisplayMode is "error" measured NOTHING (no numericValue) — the
// previous metricFinding filter (`typeof p.value === "number"`) had no else branch, so an errored
// audit was silently indistinguishable from "no page failed this metric", i.e. a clean pass. This
// surfaces it as its own disclosure so an unmeasured metric can never read as passing.
//
// Verified: under the current CLI (src/cli/lighthouse-scan.ts), an errored LCP/TBT/CLS audit also
// nulls categories.performance.score (Lighthouse's core/scoring.js: a weighted audit's null score
// nulls the whole category's arithmetic mean — confirmed live, Lighthouse 13.4.0, 2026-07-25), which
// lighthouseRunErrorReason already catches, so auditRoute() throws before this page ever reaches
// parseLighthouseFindings. This function still guards the audit level because parseLighthouseFindings
// is an independently-tested, exported pure function — it must not depend on an upstream caller's
// invariant to avoid a false clean, and a future caller (or a change to that upstream guard) could
// reach this state directly.
function metricNotMeasuredFinding(profile: MetricProfile, pages: LighthousePageResult[]): Finding | undefined {
  const errored = pages
    .map((p) => ({ label: pageLabel(p), audit: p.result.audits?.[profile.auditId] }))
    .filter((p): p is { label: string; audit: LighthouseAudit } => p.audit?.scoreDisplayMode === "error");
  if (errored.length === 0) return undefined;

  const n = errored.length;
  const detail = errored.map((e) => `${e.label}${e.audit.errorMessage ? ` (${e.audit.errorMessage})` : ""}`).join(", ");

  return {
    id: "M7L-00",
    status: "Open",
    category: "Performance",
    title: `${profile.label} NOT measured on ${n} page${n === 1 ? "" : "s"} — the Lighthouse audit errored`,
    severity: "Info",
    confidence: "N/A",
    taxonomy: `M7 — ${profile.label} not measured (Lighthouse audit error)`,
    location: errored[0]!.label,
    evidence: `Lighthouse's ${profile.auditId} audit reported scoreDisplayMode "error" (no numericValue) rather than a measurement: ${detail}. This is NOT the same as passing Google's "Good" threshold — the metric was not measured at all on this run.`,
    impact: `An errored audit gives no signal on ${profile.label}. Reading it as "within Good" (the prior behavior) is a false clean, not the absence of a problem.`,
    fix: "Re-run Lighthouse for this page and investigate why the audit errored (see the error message, and any run warnings, above) before concluding the metric is fine.",
    value: 2,
    ease: 2,
    safety: 5,
  };
}

// #1074: Lighthouse's opportunity/remediation layer (audits[].details.items, .overallSavingsMs/
// Bytes) names the SPECIFIC offending resources for the ~50 performance audits beyond the 3 tracked
// metrics — Harvey previously read none of it, so every M7L fix was the same constant prose
// regardless of what Lighthouse actually found. One finding per audit id, grouped worst-first across
// pages by savings, naming the resources Lighthouse itself flagged.
interface OpportunityProfile {
  auditId: string;
  label: string;
  impact: string;
}

const OPPORTUNITIES: OpportunityProfile[] = [
  { auditId: "render-blocking-resources", label: "Render-blocking resources", impact: "Scripts/stylesheets that block first paint until they finish loading." },
  { auditId: "unused-css-rules", label: "Unused CSS", impact: "CSS shipped but never applied on this page — extra bytes parsed before paint." },
  { auditId: "unused-javascript", label: "Unused JavaScript", impact: "JS shipped but never executed on this page — extra bytes parsed/compiled for nothing." },
  { auditId: "server-response-time", label: "Server response time (TTFB)", impact: "A slow initial server response delays everything that depends on the document." },
  { auditId: "modern-image-formats", label: "Legacy image formats", impact: "Images served in older formats are larger than a modern format (WebP/AVIF) would be." },
  { auditId: "unminified-javascript", label: "Unminified JavaScript", impact: "Unminified JS ships extra bytes with no functional benefit." },
  { auditId: "duplicated-javascript", label: "Duplicated JavaScript modules", impact: "The same module bundled more than once wastes bytes and parse time." },
];

function opportunitySavings(details: LighthouseAuditDetails): number {
  return details.overallSavingsBytes ?? details.overallSavingsMs ?? 0;
}

function opportunityFinding(profile: OpportunityProfile, pages: LighthousePageResult[]): Finding | undefined {
  const hits = pages
    .map((p) => ({ label: pageLabel(p), details: p.result.audits?.[profile.auditId]?.details }))
    .filter(
      (p): p is { label: string; details: LighthouseAuditDetails } =>
        !!p.details?.items?.length && ((p.details.overallSavingsMs ?? 0) > 0 || (p.details.overallSavingsBytes ?? 0) > 0),
    )
    .sort((a, b) => opportunitySavings(b.details) - opportunitySavings(a.details));
  if (hits.length === 0) return undefined;

  const worst = hits[0]!;
  const resources = worst.details
    .items!.slice(0, 5)
    .map((item) => {
      const size = item.wastedBytes ? `${Math.round(item.wastedBytes / 1024)} KiB` : item.wastedMs ? `${Math.round(item.wastedMs)} ms` : undefined;
      return `${item.url ?? "(unnamed resource)"}${size ? ` (${size})` : ""}`;
    })
    .join(", ");
  const savings = worst.details.overallSavingsBytes
    ? `${Math.round(worst.details.overallSavingsBytes / 1024)} KiB`
    : worst.details.overallSavingsMs
      ? `${Math.round(worst.details.overallSavingsMs)} ms`
      : "unspecified";
  const n = hits.length;

  return {
    id: "M7L-00",
    status: "Open",
    category: "Performance",
    title: `${profile.label}: ${n} page${n === 1 ? "" : "s"} (worst: ${worst.label}, ~${savings} potential savings)`,
    severity: "Low",
    confidence: "Confirmed",
    taxonomy: `M7 — Lighthouse opportunity: ${profile.label}`,
    location: worst.label,
    evidence: `Lighthouse's ${profile.auditId} audit on ${worst.label} named the specific offending resource(s): ${resources}.`,
    impact: profile.impact,
    fix: `Address the specific resource(s) Lighthouse named above (${resources}) — not generic "${profile.label.toLowerCase()}" guidance.`,
    value: 3,
    ease: 3,
    safety: 4,
  };
}

function perfScoreFinding(pages: LighthousePageResult[]): Finding | undefined {
  const failing = pages
    .map((p) => ({ label: pageLabel(p), score: p.result.categories?.performance?.score }))
    .filter((p): p is { label: string; score: number } => typeof p.score === "number" && p.score < PERF_SCORE_GOOD)
    .sort((a, b) => a.score - b.score);
  if (failing.length === 0) return undefined;

  const worst = failing[0]!;
  const severity: Severity = failing.some((p) => p.score < PERF_SCORE_POOR) ? "Perf" : "Low";
  const n = failing.length;

  return {
    id: "M7L-00",
    status: "Open",
    category: "Performance",
    title: `${n} page${n === 1 ? "" : "s"} below Lighthouse performance score ${PERF_SCORE_GOOD} (worst: ${worst.score.toFixed(2)})`,
    severity,
    confidence: "Confirmed",
    taxonomy: "M7 — Lighthouse performance score below Good",
    location: worst.label,
    evidence:
      `Lighthouse performance score (0–1), worst-first: ` +
      pageList(failing.map((p) => ({ label: p.label, text: p.score.toFixed(2) }))) +
      `. A weighted roll-up of the lab metrics; measured this run under simulated throttling.` +
      runWarningsNote(pages, failing.map((p) => p.label)),
    impact: "The overall Lighthouse performance score is a weighted roll-up of the lab metrics (LCP/TBT/CLS/FCP/SI). Below 0.9 is 'needs improvement'; below 0.5 is 'poor'.",
    fix: "Address the individual metric findings (LCP/TBT/CLS) that drive the score — the score has no separate fix of its own.",
    value: 3,
    ease: 2,
    safety: 4,
  };
}

// One Finding per failing metric (grouped across all pages, worst-first) plus one for the overall
// performance score — the same "group by rule, list worst-first, count in the title" shape as the
// DB-advisor pass (src/perf-scan.ts) and the bundle-stats pass, so the §3b Performance table reads
// "5 pages with poor LCP, worst /dashboard 4.8s", not one row per (page × metric). Ids M7L-01…,
// score last. A metric no page fails produces no finding (clean = absent, per the report shape).
// #1074: each metric also gets its own metricNotMeasuredFinding, so an errored audit is disclosed
// rather than silently read as clean; opportunity findings (Lighthouse's named offending resources)
// are appended after the metric/score findings.
export function parseLighthouseFindings(pages: LighthousePageResult[]): Finding[] {
  const findings = [
    ...METRICS.flatMap((m) => [metricFinding(m, pages), metricNotMeasuredFinding(m, pages)]),
    perfScoreFinding(pages),
    ...OPPORTUNITIES.map((o) => opportunityFinding(o, pages)),
  ].filter((f): f is Finding => f !== undefined);
  return findings.map((f, i) => ({ ...f, id: `M7L-${String(i + 1).padStart(2, "0")}` }));
}

// #1074: src/cli/lighthouse-scan.ts invokes Lighthouse with onlyCategories: ["performance"] — the
// accessibility, best-practices, and SEO categories never run at all, and LighthouseResult could not
// have held them anyway (only `categories.performance` is modelled). `grep -r
// accessibility|a11y|axe-core src/ briefs/` finds no other module covering this, so it is a total
// gap — disclosed here rather than silently, mirroring INFRA-SCOPE-00 (src/scan/infra-scope.ts) /
// M1-LANG-00 (src/scan/language-coverage.ts). One constant row per run — src/cli/lighthouse-scan.ts
// appends it whenever the Lighthouse tier actually ran (the unavailable-tier disclosure already
// covers the case where it didn't run at all).
export function lighthouseScopeDisclosureFinding(): Finding {
  return {
    id: "M7-SCOPE-00",
    status: "Open",
    category: "Performance",
    title: "Lighthouse pass scoped to Performance only — accessibility/best-practices/SEO not assessed",
    severity: "Info",
    confidence: "N/A",
    taxonomy: "M7 — Lighthouse categories out of scope",
    location: "target app",
    evidence: `This Lighthouse pass runs with onlyCategories: ["performance"] — the accessibility, best-practices, and SEO categories do not run at all. best-practices in particular includes csp-xss, is-on-https, deprecations, and errors-in-console — checks directly relevant to M1 that this audit does not get from Lighthouse.`,
    impact: "Accessibility, best-practices, and SEO are a total gap in M7's Lighthouse tier. No other Harvey module runs an accessibility/axe-core pass, so this is not covered elsewhere in the report.",
    fix: "Widen onlyCategories to include accessibility/best-practices/seo (adds runtime per page), or run a dedicated a11y pass (axe-core, or Lighthouse CI with the full category set) alongside this tier.",
    value: 2,
    ease: 3,
    safety: 5,
  };
}

// A Lighthouse run can return a result object that measured NOTHING — a runtimeError like NO_FCP
// ("the page did not paint any content"), or a null performance score. Its metric audits then have
// no numericValue, which parseLighthouseFindings reads as "every metric within Good" — a FALSE
// clean, the exact failure the coverage doctrine forbids. This returns the human reason when a page
// result did not actually measure, so the CLI records the fail-loud M7L-00 disclosure instead of an
// empty (clean-looking) finding set. A successful run always carries a numeric performance score.
// (#488 — observed live: the Playwright "Chrome for Testing" build yields NO_FCP.)
export function lighthouseRunErrorReason(result: LighthouseResult): string | undefined {
  if (result.runtimeError?.code) {
    return result.runtimeError.message
      ? `${result.runtimeError.code} — ${result.runtimeError.message}`
      : result.runtimeError.code;
  }
  if (result.categories?.performance?.score == null) return "the run produced no performance score";
  return undefined;
}

// The `npm run <script>` a target uses to serve its production build for the Lighthouse pass. Next
// serves the `next start` build via the `start` script (`-p <port>`); a Vite app has no `start` —
// its build is served by `vite preview --port <port>` (the `preview` script) (#577). Astro,
// SvelteKit and Nuxt ship the same `preview` convention, so #872's new framework values keep the
// serve command they had when they all resolved to `vite`; Remix / React Router 7 / TanStack Start
// serve through `start`, like Next. `other`/unknown falls back to `start`, the create-react-app /
// generic convention. The build step (`npm run build`) is the same for both, so only the serve
// command branches.
const PREVIEW_SERVED: TargetFramework[] = ["vite", "astro", "sveltekit", "nuxt"];

export function serveCommand(framework: TargetFramework, port: number): { args: string[]; label: string } {
  const args = PREVIEW_SERVED.includes(framework)
    ? ["run", "preview", "--", "--port", String(port)]
    : ["run", "start", "--", "-p", String(port)];
  return { args, label: `npm ${args.join(" ")}` };
}

// The fail-loud disclosure the coverage doctrine requires: when the target can't be built, served,
// or driven (no build script, build failed, no Chrome, port in use), M7's CWV tier is UNMEASURED —
// recorded as a finding with the reason, never a silent skip. Mirrors M7B-03 / M5-00 / M8-00.
export function lighthouseUnavailableFinding(reason: string): Finding {
  return {
    id: "M7L-00",
    status: "Open",
    category: "Performance",
    title: "Core Web Vitals not measured — Lighthouse pass could not run",
    severity: "Info",
    confidence: "N/A",
    taxonomy: "M7 — Core Web Vitals not measured",
    location: "target app",
    evidence: `The Lighthouse (Core Web Vitals) tier could not run: ${reason}`,
    impact: "LCP/CLS/TBT were not measured for this engagement — a coverage disclosure, not a clean result. The other M7 tiers (code, bundle, DB advisors) still ran.",
    fix: "Supply a buildable/servable target (or a running URL via --url) and a Chrome/Chromium binary, then re-run `pnpm lighthouse-scan`.",
    value: 1,
    ease: 3,
    safety: 5,
  };
}
