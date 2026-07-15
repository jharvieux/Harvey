// Findings schema for the audit deliverable. report-template/render.mjs consumes
// this shape; validate an engagement's findings.json here before rendering.

export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Perf", "Info", "Watch"] as const;
export const CONFIDENCES = ["Confirmed", "Likely", "Review", "N/A"] as const;
// Trust tier for mechanically-generated findings: "high" = ~100%-precision source (verified
// secret, decoded service-role JWT, exact CVE match, advisor lint, HIGH-confidence ERROR
// Semgrep rule) — safe to count without triage. "review" = heuristic/grep-sourced, needs triage.
export const PRECISION_TIERS = ["high", "review"] as const;

export type Severity = (typeof SEVERITIES)[number];
export type Confidence = (typeof CONFIDENCES)[number];
export type PrecisionTier = (typeof PRECISION_TIERS)[number];

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  taxonomy: string;
  location: string;
  status: string;
  evidence: string;
  impact: string;
  fix: string;
  // BFTB inputs, each 1–5: business value of fixing, ease of fix, safety of fix.
  value: number;
  ease: number;
  safety: number;
  okWhen?: string;
  notOkWhen?: string;
  note?: string;
  // Set by scan modules (src/scan/**) on findings produced by a deterministic tool pass,
  // as opposed to a human/LLM-authored engagement finding.
  mechanical?: boolean;
  precisionTier?: PrecisionTier;
  // A finding's own claim that it is more than a version/pattern match — that exploitability in
  // THIS codebase has actually been confirmed, not just a fact about which CVE range a dependency
  // falls in. Grading logic (src/quick-scan.ts NON_GRADING_CATEGORIES) treats a whole category as
  // "fact-only" by default but defers to this per-finding override, so a future exploitability-
  // verified finding in a non-grading category isn't silently un-graded (#260). Unset/false is the
  // safe default — set it explicitly, per finding, only when exploitability was actually confirmed.
  exploitabilityVerified?: boolean;
}

export interface ReportMeta {
  client: string;
  subtitle: string;
  date: string;
  commit: string;
  auditor: string;
  confidential: boolean;
  overallHealth: number;
  tenantIsolation: string;
  authModel: string;
  headline: string;
  scope: string;
  methodology: string;
  outOfScope: string;
}

export interface FindingsDocument {
  meta: ReportMeta;
  findings: Finding[];
}

// Bang-for-the-buck score, 0–100. Mirrors the formula in report-template/render.mjs.
export function bftb(f: Pick<Finding, "value" | "ease" | "safety">): number {
  return Math.round(((f.value * f.ease * f.safety) / 125) * 100);
}

export interface ValidationResult {
  ok: boolean;
  errors: string[];
}

const META_STRING_FIELDS: (keyof ReportMeta)[] = [
  "client", "subtitle", "date", "commit", "auditor", "tenantIsolation",
  "authModel", "headline", "scope", "methodology", "outOfScope",
];

const FINDING_STRING_FIELDS: (keyof Finding)[] = [
  "id", "title", "category", "taxonomy", "location", "status", "evidence", "impact", "fix",
];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function scoreInRange(v: unknown): boolean {
  return typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= 5;
}

export function validateFindings(data: unknown): ValidationResult {
  const errors: string[] = [];

  if (!isRecord(data)) return { ok: false, errors: ["document is not an object"] };

  if (!isRecord(data.meta)) {
    errors.push("meta: missing or not an object");
  } else {
    for (const k of META_STRING_FIELDS) {
      if (typeof data.meta[k] !== "string") errors.push(`meta.${k}: expected string`);
    }
    if (typeof data.meta.confidential !== "boolean") errors.push("meta.confidential: expected boolean");
    const h = data.meta.overallHealth;
    if (typeof h !== "number" || h < 0 || h > 10) errors.push("meta.overallHealth: expected number 0–10");
  }

  if (!Array.isArray(data.findings)) {
    errors.push("findings: missing or not an array");
    return { ok: false, errors };
  }

  const seenIds = new Set<string>();
  data.findings.forEach((f: unknown, i: number) => {
    const at = `findings[${i}]`;
    if (!isRecord(f)) {
      errors.push(`${at}: not an object`);
      return;
    }
    for (const k of FINDING_STRING_FIELDS) {
      if (typeof f[k] !== "string") errors.push(`${at}.${k}: expected string`);
    }
    if (!SEVERITIES.includes(f.severity as Severity)) {
      errors.push(`${at}.severity: "${String(f.severity)}" not one of ${SEVERITIES.join("/")}`);
    }
    if (!CONFIDENCES.includes(f.confidence as Confidence)) {
      errors.push(`${at}.confidence: "${String(f.confidence)}" not one of ${CONFIDENCES.join("/")}`);
    }
    for (const k of ["value", "ease", "safety"] as const) {
      if (!scoreInRange(f[k])) errors.push(`${at}.${k}: expected integer 1–5`);
    }
    if (typeof f.id === "string") {
      if (seenIds.has(f.id)) errors.push(`${at}.id: duplicate id "${f.id}"`);
      seenIds.add(f.id);
    }
    if (f.mechanical !== undefined && typeof f.mechanical !== "boolean") {
      errors.push(`${at}.mechanical: expected boolean`);
    }
    if (f.exploitabilityVerified !== undefined && typeof f.exploitabilityVerified !== "boolean") {
      errors.push(`${at}.exploitabilityVerified: expected boolean`);
    }
    if (f.precisionTier !== undefined && !PRECISION_TIERS.includes(f.precisionTier as PrecisionTier)) {
      errors.push(`${at}.precisionTier: "${String(f.precisionTier)}" not one of ${PRECISION_TIERS.join("/")}`);
    }
  });

  return { ok: errors.length === 0, errors };
}
