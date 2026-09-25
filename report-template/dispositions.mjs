import { createHash } from "node:crypto";

export const DISPOSITIONS = ["confirmed", "actionable", "pending-review", "false-positive", "inventory", "superseded", "not-applicable"];
export const DISPOSITION_LABELS = {
  confirmed: "Confirmed defects", actionable: "Current health findings", "pending-review": "Pending review",
  "false-positive": "False positives", inventory: "Data inventory", superseded: "Superseded evidence", "not-applicable": "Not applicable / not assessed",
};

export function findingModule(f) {
  const explicit = /^M(?:10|[1-9])$/.test(f.module ?? "") ? f.module : undefined;
  return explicit ?? /^(M(?:10|[1-9]))(?:\b|[-—])/.exec(f.taxonomy ?? "")?.[1]
    ?? (f.category === "Security" ? "M1" : f.category === "Data classification" ? "M10" : undefined);
}

const text = (value) => typeof value === "string" && value.trim().length > 0;

/** Review claims need attributable evidence; scanner confidence is a separate measurement. */
export function assessmentErrors(a) {
  if (!a || typeof a !== "object" || Array.isArray(a)) return ["expected an assessment object"];
  const errors = [];
  if (!DISPOSITIONS.includes(a.disposition)) errors.push("unknown disposition");
  if (!["scanner", "source-review", "runtime", "inventory", "historical", "scope"].includes(a.evidenceKind)) errors.push("unknown evidenceKind");
  if (!["unreviewed", "reviewed"].includes(a.reviewStatus)) errors.push("unknown reviewStatus");
  if (!["current", "historical", "unknown"].includes(a.sourceScope)) errors.push("unknown sourceScope");
  if (!text(a.reason)) errors.push("reason is required");
  if (a.reviewStatus === "reviewed" && (!text(a.review?.reviewer) || !Array.isArray(a.review?.evidence) || !a.review.evidence.length || a.review.evidence.some((x) => !text(x)))) errors.push("review requires a reviewer and evidence references");
  if (a.disposition === "confirmed" && (a.reviewStatus !== "reviewed" || !["source-review", "runtime"].includes(a.evidenceKind) || a.sourceScope !== "current")) errors.push("confirmed requires reviewed current source/runtime evidence");
  if (a.disposition === "false-positive" && a.reviewStatus !== "reviewed") errors.push("false-positive requires review");
  if (a.disposition === "superseded" && (a.sourceScope !== "historical" || !text(a.supersededBy?.artifact) || !text(a.supersededBy?.reason))) errors.push("superseded requires a historical scope and replacement artifact/reason");
  if (["confirmed", "actionable"].includes(a.disposition) && a.sourceScope !== "current") errors.push("current finding requires current sourceScope");
  return errors;
}

export function assessmentFor(f) {
  if (f.assessment !== undefined) {
    const errors = assessmentErrors(f.assessment);
    if (errors.length) throw new Error(`Invalid assessment for ${f.id}: ${errors.join("; ")}`);
    return f.assessment;
  }
  const module = findingModule(f);
  if (f.confidence === "N/A") return { disposition: "not-applicable", evidenceKind: "scope", reviewStatus: "unreviewed", sourceScope: "unknown", reason: f.note || f.evidence };
  if ((module === "M10" && f.category === "Data classification") || f.reviewFlagOnly) return { disposition: "inventory", evidenceKind: "inventory", reviewStatus: "unreviewed", sourceScope: "current", reason: "Data classification records sensitivity and review needs; it does not establish a vulnerability." };
  if ((module && !["M1", "M10"].includes(module)) || (!module && ["Quality", "Performance", "Reliability", "Maintainability", "Testing"].includes(f.category))) return { disposition: "actionable", evidenceKind: "scanner", reviewStatus: "unreviewed", sourceScope: "current", reason: "Current codebase-health finding; module severity and priority are preserved. Independent review is not recorded." };
  return { disposition: "pending-review", evidenceKind: "scanner", reviewStatus: "unreviewed", sourceScope: "unknown", reason: "Scanner output awaits attributable source or runtime review. Severity and scanner confidence do not establish independent confirmation." };
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().filter((key) => value[key] !== undefined).map((key) => [key, canonical(value[key])]));
  return value;
}

/** Content survives producer rekeys; only documented assembly annotations are excluded. */
export function contentIdentity(f) {
  const body = { ...f, severity: f.dataClass?.escalatedFrom ?? f.severity };
  for (const key of ["id", "origin", "assessment", "baselineStatus", "baselineReason", "lowConfidenceMatch", "onHotspot", "hotspotRank", "dataClass", "_bftb", "_linked"]) delete body[key];
  return createHash("sha256").update(JSON.stringify(canonical(body))).digest("hex");
}

/** Each distinct capture retains a stable content key and a separate occurrence identity. */
export function prepareFindings(findings) {
  const idCounts = new Map();
  for (const f of findings) idCounts.set(f.id, (idCounts.get(f.id) ?? 0) + 1);
  const ordinals = new Map();
  return findings.map((f) => {
    const contentKey = contentIdentity(f);
    const ordinal = (ordinals.get(contentKey) ?? 0) + 1;
    ordinals.set(contentKey, ordinal);
    const origin = { contentKey, occurrenceKey: `${contentKey}:${ordinal}`, producerId: f.origin?.producerId ?? f.id };
    const id = idCounts.get(f.id) > 1 ? `${f.id}~${contentKey.slice(0, 16)}-${ordinal}` : f.id;
    return { ...f, id, origin, assessment: assessmentFor(f) };
  });
}

export function populationSummary(findings) {
  const counts = Object.fromEntries(DISPOSITIONS.map((key) => [key, 0]));
  for (const f of findings) counts[assessmentFor(f).disposition]++;
  return { total: findings.length, counts };
}

/** A comparison summary must balance its populations before the renderer makes progress claims. */
export function baselineIntegrityErrors(baseline, findings) {
  if (!baseline?.comparison) return [];
  const c = baseline.comparison;
  const d = c.denominators;
  const n = baseline.counts;
  const errors = [];
  const integer = (x) => Number.isInteger(x) && x >= 0;
  if (!d || !n || ![d.prior, d.current, d.matched, d.unresolvedPrior, d.unresolvedCurrent, d.comparablePrior, d.comparableCurrent, n.new, n.persistent, n.resolved].every(integer)
    || !Array.isArray(baseline.resolved) || !Array.isArray(baseline.unresolved)
    || d.current !== findings.length || d.prior !== d.matched + baseline.resolved.length + baseline.unresolved.length
    || d.current !== d.matched + d.unresolvedCurrent + n.new || n.persistent !== d.matched
    || n.resolved !== baseline.resolved.length || d.unresolvedPrior !== baseline.unresolved.length
    || n.new !== findings.filter((f) => f.baselineStatus === "new").length) errors.push("comparison population denominators do not reconcile");
  if (!Array.isArray(c.limitations) || !c.limitations.length) errors.push("comparison limitations are required");
  if (c.kind !== "source-change" && (n?.new || n?.resolved)) errors.push("uncomparable evidence cannot claim new/resolved defects");
  if (c.kind === "source-change") {
    const a = c.prior, b = c.current;
    if (!a || !b || !a.scopeComplete || !b.scopeComplete || a.kind !== "client-audit" || b.kind !== "client-audit"
      || !text(a.engagementId) || !text(b.engagementId) || a.engagementId === b.engagementId
      || !text(a.target?.id) || a.target.id !== b.target?.id || !text(a.target.revision) || !text(b.target.revision) || a.target.revision === b.target.revision
      || !text(a.schemaVersion) || a.schemaVersion !== b.schemaVersion || !a.producerVersions || !b.producerVersions || !Object.keys(a.producerVersions).length
      || JSON.stringify(canonical(a.producerVersions)) !== JSON.stringify(canonical(b.producerVersions))
      || !Array.isArray(a.assessedScope) || !a.assessedScope.length || !Array.isArray(b.assessedScope) || JSON.stringify([...new Set(a.assessedScope)].sort()) !== JSON.stringify([...new Set(b.assessedScope)].sort())) errors.push("source-change claims require matching complete scope and producer/schema provenance across distinct client audits and source revisions");
    if ([...findings.filter((f) => f.baselineStatus === "new"), ...(baseline.resolved ?? [])].some((f) => !f || (f.assessment !== undefined && assessmentErrors(f.assessment).length > 0) || !["confirmed", "actionable"].includes(assessmentFor(f).disposition))) errors.push("new/resolved defect counts cannot include pending review or inventory");
  }
  return errors;
}
