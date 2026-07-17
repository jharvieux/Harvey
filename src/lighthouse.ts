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

interface LighthouseAudit {
  score?: number | null;
  numericValue?: number;
  displayValue?: string;
}

// The subset of the Lighthouse result object (LHR) this transform reads. The real object is large;
// only these fields matter for CWV finding shaping.
export interface LighthouseResult {
  finalDisplayedUrl?: string;
  finalUrl?: string;
  requestedUrl?: string;
  categories?: { performance?: { score?: number | null } };
  audits?: Record<string, LighthouseAudit>;
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
      `. Measured this run under simulated throttling — corroborate with field RUM or repeat runs before acting.`,
    impact: profile.impact,
    fix: profile.fix,
    value: profile.value,
    ease: profile.ease,
    safety: profile.safety,
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
      `. A weighted roll-up of the lab metrics; measured this run under simulated throttling.`,
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
export function parseLighthouseFindings(pages: LighthousePageResult[]): Finding[] {
  const findings = [...METRICS.map((m) => metricFinding(m, pages)), perfScoreFinding(pages)].filter(
    (f): f is Finding => f !== undefined,
  );
  return findings.map((f, i) => ({ ...f, id: `M7L-${String(i + 1).padStart(2, "0")}` }));
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
