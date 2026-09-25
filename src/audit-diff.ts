// Compare evidence only after recording source, producer and assessed-scope compatibility.
import { lstatSync, realpathSync } from "node:fs";
import { createHash } from "node:crypto";
import { basename, dirname, isAbsolute, join, posix, relative, resolve, win32 } from "node:path";
import { assessmentFor, contentIdentity } from "../report-template/dispositions.mjs";
import type { AuditContext, BaselineSummary, Finding, FindingsDocument, IdentityMigration } from "./findings.js";

export interface FindingIdentityOptions {
  /** Authoritative root that file locations are relative to. */
  root?: string;
  /** Override the root filesystem's case policy. Auto-detected when possible. */
  caseSensitive?: boolean;
  priorContext?: AuditContext;
  currentContext?: AuditContext;
  migrations?: IdentityMigration[];
}

function withoutLinePosition(location: string): string {
  return location
    .replace(/#l\d+(?:-l?\d+)?/gi, "") // GitHub blob anchors: #L42, #L42-L48
    .replace(/:\d+(?::\d+)?/g, "") // path:line or path:line:col
    .replace(/\(?\blines?\s+\d+(?:\s*[-–]\s*\d+)?\)?/gi, "") // "(line 42)", "lines 10-20"
    .replace(/\s+/g, " ")
    .trim();
}

function looksLikeFileLocation(value: string): boolean {
  return /[/\\]/.test(value) || /(?:^|[/\\])[^/\\\s]+\.[a-z0-9_-]+$/i.test(value);
}

function alternateCase(value: string): string | undefined {
  const at = value.search(/[a-z]/i);
  if (at < 0) return undefined;
  const c = value[at]!;
  const swapped = c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase();
  return `${value.slice(0, at)}${swapped}${value.slice(at + 1)}`;
}

function rootIsCaseSensitive(root: string): boolean {
  const alt = alternateCase(basename(root));
  if (!alt || alt === basename(root)) return true;
  try {
    const exact = lstatSync(root);
    const caseVariant = lstatSync(join(dirname(root), alt));
    // On a case-insensitive filesystem both spellings resolve to the same inode. A distinct sibling
    // differing only by case proves the opposite and must never be collapsed.
    return exact.dev !== caseVariant.dev || exact.ino !== caseVariant.ino;
  } catch {
    return true;
  }
}

function realpathIfPresent(path: string): string | undefined {
  try {
    return realpathSync.native(path);
  } catch {
    return undefined;
  }
}

function isOutside(relativePath: string): boolean {
  return relativePath === ".." || relativePath.startsWith("../") || isAbsolute(relativePath);
}

function pathUsesSymlink(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  if (isOutside(rel)) return false;
  let cursor = root;
  const parts = rel.split(/[\\/]/).filter(Boolean);
  try {
    if (lstatSync(cursor).isSymbolicLink()) return true;
    for (const part of parts) {
      cursor = join(cursor, part);
      if (lstatSync(cursor).isSymbolicLink()) return true;
    }
  } catch {
    return false;
  }
  return false;
}

function canonicalWindowsPath(path: string, options: FindingIdentityOptions): string {
  const windowsPath = path.replace(/\//g, "\\");
  const root = options.root?.replace(/\//g, "\\");
  if (!root) {
    const normalized = win32.normalize(windowsPath).replace(/\\/g, "/");
    return `unbound:${(options.caseSensitive ?? false) ? normalized : normalized.toLowerCase()}`;
  }

  const rootPath = win32.resolve(root);
  const candidate = win32.isAbsolute(windowsPath) ? win32.normalize(windowsPath) : win32.resolve(rootPath, windowsPath);
  const rel = win32.relative(rootPath, candidate).replace(/\\/g, "/") || ".";
  const caseSensitive = options.caseSensitive ?? false;
  const canonical = caseSensitive ? rel : rel.toLowerCase();
  return isOutside(rel) || win32.isAbsolute(rel) ? `external:${canonical}` : canonical;
}

function canonicalPosixPath(path: string, options: FindingIdentityOptions): string {
  const normalized = posix.normalize(path.replace(/\\/g, "/"));
  if (!options.root) {
    if (normalized === ".." || normalized.startsWith("../") || normalized.startsWith("/")) {
      return `unbound:${normalized}`;
    }
    return options.caseSensitive === false ? normalized.toLowerCase() : normalized;
  }

  const rootLexical = resolve(options.root);
  const rootReal = realpathIfPresent(rootLexical) ?? rootLexical;
  const candidateLexical = isAbsolute(normalized) ? resolve(normalized) : resolve(rootLexical, normalized);
  const lexicalRel = relative(rootLexical, candidateLexical);
  const observedReal = realpathIfPresent(candidateLexical);
  // A case-insensitive host can resolve a spelling that would be distinct under an explicit
  // case-sensitive policy. Keep the lexical spelling unless an actual symlink requires realpath.
  const useObservedReal = options.caseSensitive !== true || pathUsesSymlink(rootLexical, candidateLexical);
  const candidate = (useObservedReal ? observedReal : undefined)
    ?? (isOutside(lexicalRel) ? candidateLexical : resolve(rootReal, lexicalRel));
  const rel = relative(rootReal, candidate).replace(/\\/g, "/") || ".";
  const caseSensitive = options.caseSensitive ?? rootIsCaseSensitive(rootReal);
  const canonical = caseSensitive ? rel : rel.toLowerCase();
  return isOutside(rel) ? `external:${canonical}` : canonical;
}

function canonicalFileLocation(path: string, options: FindingIdentityOptions): string {
  const root = options.root?.replace(/\\/g, "/");
  const windows = /^[a-z]:[/\\]/i.test(path) || /^[a-z]:[/\\]/i.test(root ?? "") || path.startsWith("\\\\");
  return windows ? canonicalWindowsPath(path, options) : canonicalPosixPath(path, options);
}

// Strip positional churn and canonicalize file paths at the project-root boundary. File case is
// governed by the authoritative root, while descriptive non-file locations retain legacy folding.
export function normalizeLocation(location: string, options: FindingIdentityOptions = {}): string {
  const stripped = withoutLinePosition(location).replace(/^\[[^\]]*\]\s*/, "");
  const suffix = /\s+(\([^)]*\))$/.exec(stripped);
  const candidate = suffix ? stripped.slice(0, suffix.index).trim() : stripped;
  if (!looksLikeFileLocation(candidate)) return stripped.toLowerCase();

  const canonical = canonicalFileLocation(candidate, options);
  return suffix ? `${canonical} ${suffix[1]!.toLowerCase()}` : canonical;
}

function normalizeTaxonomy(f: Finding): string {
  const t = (f.taxonomy || f.category || "").toLowerCase().trim();
  return t.replace(/\s+/g, " ");
}

// A candidate-location key; semantic evidence and provenance are checked before matching.
export function findingIdentity(f: Finding, options: FindingIdentityOptions = {}): string {
  return `${normalizeTaxonomy(f)}::${normalizeLocation(f.location, options)}`;
}

interface BaselineDiff {
  findings: Finding[];
  resolved: Finding[];
  unresolved: Finding[];
  counts: { resolved: number; persistent: number; new: number };
  comparison: NonNullable<BaselineSummary["comparison"]>;
}

function contextComplete(c: AuditContext | undefined): c is AuditContext {
  return !!c && typeof c.engagementId === "string" && !!c.engagementId.trim()
    && ["client-audit", "same-run-checkpoint"].includes(c.kind)
    && !!c.target?.id && !!c.target.revision && !!c.schemaVersion
    && !!c.producerVersions && Object.keys(c.producerVersions).length > 0
    && Object.values(c.producerVersions).every((v) => typeof v === "string" && !!v.trim())
    && Array.isArray(c.assessedScope) && c.assessedScope.length > 0
    && c.assessedScope.every((v) => typeof v === "string" && !!v.trim()) && typeof c.scopeComplete === "boolean";
}

function comparisonContext(options: FindingIdentityOptions): Pick<BaselineDiff["comparison"], "kind" | "limitations"> {
  const a = options.priorContext;
  const b = options.currentContext;
  const answer = (kind: BaselineDiff["comparison"]["kind"], reason: string): Pick<BaselineDiff["comparison"], "kind" | "limitations"> => ({
    kind, limitations: [...new Set([reason, ...(a?.limitations ?? []).map((item) => `Prior audit: ${item}`), ...(b?.limitations ?? []).map((item) => `Current audit: ${item}`)])],
  });
  if (!contextComplete(a) || !contextComplete(b)) return answer("incompatible", "Missing engagement, target revision, producer/schema versions or assessed-scope provenance. Unmatched identities remain unresolved; absence is not remediation.");
  if (a.target.id !== b.target.id) return answer("incompatible", "Baseline and current evidence name different targets.");
  if ([a, b].some((context) => context.provenance && (!context.provenance.target.complete || !context.provenance.target.stable || !context.provenance.engine.complete || !context.provenance.engine.stable))) return answer("incompatible", "Source or engine observation was incomplete or changed during execution; one comparable revision is unproved.");
  if (a.engagementId === b.engagementId || a.kind === "same-run-checkpoint" || b.kind === "same-run-checkpoint") return answer("same-run-checkpoint", "This comparison includes a checkpoint from the same engagement, not a prior client audit. It measures capture changes, not client remediation.");
  if (a.producerAssignments && b.producerAssignments) {
    const priorAssignments = a.producerAssignments, currentAssignments = b.producerAssignments;
    const changed = Object.keys(priorAssignments).some((scope) => Object.hasOwn(currentAssignments, scope)
      && JSON.stringify([...new Set(priorAssignments[scope])].sort()) !== JSON.stringify([...new Set(currentAssignments[scope])].sort()));
    if (changed) return answer("tool-change", "Producer versions assigned to an existing assessed scope changed. New and absent observations are not attributed to source regressions or remediation.");
  } else {
    const ambiguous = (context: AuditContext): boolean => {
      const versions = new Map<string, Set<string>>();
      for (const key of Object.keys(context.producerVersions)) {
        let pair: unknown;
        try { pair = JSON.parse(key); } catch { continue; }
        if (!Array.isArray(pair) || pair.length !== 2 || pair.some((value) => typeof value !== "string")) continue;
        const values = versions.get(pair[0] as string) ?? new Set<string>();
        values.add(pair[1] as string); versions.set(pair[0] as string, values);
      }
      return [...versions.values()].some((values) => values.size > 1);
    };
    if (!!a.producerAssignments !== !!b.producerAssignments || ambiguous(a) || ambiguous(b)) return answer("incompatible", "Producer-to-scope version assignments are unavailable for one or both audits. Global producer versions cannot establish which version examined each scope.");
  }
  const producerKey = (c: AuditContext): string => JSON.stringify(Object.entries(c.producerVersions).sort(([a], [b]) => a.localeCompare(b)));
  const versionSets = (context: AuditContext): Map<string, Set<string>> => {
    const versions = new Map<string, Set<string>>();
    for (const [key, version] of Object.entries(context.producerVersions)) {
      let pair: unknown;
      try { pair = JSON.parse(key); } catch { continue; }
      if (!Array.isArray(pair) || pair.length !== 2 || typeof pair[0] !== "string" || pair[1] !== version) continue;
      const values = versions.get(pair[0]) ?? new Set<string>();
      values.add(version); versions.set(pair[0], values);
    }
    return versions;
  };
  const priorVersions = versionSets(a), currentVersions = versionSets(b);
  const changedProducerVersion = [...priorVersions].some(([name, versions]) => currentVersions.has(name)
    && JSON.stringify([...versions].sort()) !== JSON.stringify([...currentVersions.get(name)!].sort()));
  const changedVersion = Object.keys(a.producerVersions).some((key) => key in b.producerVersions && a.producerVersions[key] !== b.producerVersions[key]);
  if (a.schemaVersion !== b.schemaVersion || changedVersion || changedProducerVersion) return answer("tool-change", "Producer, rule or schema versions changed. New and absent observations are not attributed to source regressions or remediation.");
  if (!a.scopeComplete || !b.scopeComplete || JSON.stringify([...new Set(a.assessedScope)].sort()) !== JSON.stringify([...new Set(b.assessedScope)].sort())) return answer("scope-change", "Assessed scope changed or is incomplete. Expanded and missing observations do not establish new or resolved defects.");
  if (producerKey(a) !== producerKey(b)) return answer("tool-change", "The producer population changed within the declared scope. New and absent observations are not attributed to source changes.");
  if (a.provenance?.configurationSha256 !== b.provenance?.configurationSha256 || JSON.stringify(a.provenance?.inputBindings) !== JSON.stringify(b.provenance?.inputBindings)) return answer("scope-change", "Effective configuration or consumed external inputs changed or lack comparable bindings; source-only attribution is unproved.");
  if (a.target.revision === b.target.revision) return answer("same-source", "The target revision is unchanged. Unmatched observations require identity or capture review; no source regression/remediation is claimed.");
  return answer("source-change", "Counts cover only reviewed defects and current health findings within identical, complete assessed scope and producer/schema versions. Ambiguous identities and pending reviews remain unresolved.");
}

export function semanticFindingIdentity(f: Finding, options: FindingIdentityOptions = {}): string {
  const normalized = (s: string): string => s.replace(/\s+/g, " ").trim();
  return createHash("sha256").update(JSON.stringify([findingIdentity(f, options), f.category, f.module, f.dependency, f.cwe, normalized(f.title), normalized(f.evidence), normalized(f.impact), normalized(f.fix)])).digest("hex");
}

export function diffAgainstBaseline(baseline: Finding[], current: Finding[], options: FindingIdentityOptions = {}): BaselineDiff {
  const compatibility = comparisonContext(options);
  if (options.priorContext && options.currentContext && !options.priorContext.producerAssignments && !options.currentContext.producerAssignments) compatibility.limitations.push("Legacy audit contexts do not bind producer versions to individual assessed scopes; that assignment was not verified.");
  const matched = new Set<number>();
  const indexKeys = (keys: string[]): Map<string, number[]> => {
    const index = new Map<string, number[]>();
    keys.forEach((key, i) => { const bucket = index.get(key) ?? []; bucket.push(i); index.set(key, bucket); });
    return index;
  };
  const priorContent = indexKeys(baseline.map(contentIdentity));
  const currentContentKeys = current.map(contentIdentity);
  const currentContent = indexKeys(currentContentKeys);
  const priorSemantic = indexKeys(baseline.map((f) => semanticFindingIdentity(f, options)));
  const priorTaxonomy = indexKeys(baseline.map(normalizeTaxonomy));
  const currentTaxonomy = new Set(current.map(normalizeTaxonomy));
  const migrationRows = options.migrations ?? [];
  const validMigrations = migrationRows.filter((m) => typeof m.reason === "string" && m.reason.trim() && typeof m.reviewedBy === "string" && m.reviewedBy.trim()
    && priorContent.get(m.priorContentKey)?.length === 1 && currentContent.get(m.currentContentKey)?.length === 1
    && migrationRows.filter((x) => x.priorContentKey === m.priorContentKey || x.currentContentKey === m.currentContentKey).length === 1);
  const migrationsByCurrent = new Map(validMigrations.map((m) => [m.currentContentKey, m]));
  const reservedForMigration = new Set(validMigrations.map((m) => priorContent.get(m.priorContentKey)![0]!));
  const eligible = (f: Finding): boolean => ["confirmed", "actionable"].includes(assessmentFor(f).disposition);
  const canClaim = compatibility.kind === "source-change";
  let matchCount = 0;
  const findings = current.map((f, at): Finding => {
    const key = semanticFindingIdentity(f, options);
    const migration = migrationsByCurrent.get(currentContentKeys[at]!);
    const specificLocation = looksLikeFileLocation(withoutLinePosition(f.location));
    const bucket = migration ? priorContent.get(migration.priorContentKey) : specificLocation ? priorSemantic.get(key) : undefined;
    while (bucket?.length && (matched.has(bucket[bucket.length - 1]!) || (!migration && reservedForMigration.has(bucket[bucket.length - 1]!)))) bucket.pop();
    const index = bucket?.pop() ?? -1;
    if (index >= 0 && options.priorContext?.target?.id && options.priorContext.target.id === options.currentContext?.target?.id) {
      matched.add(index); matchCount++;
      return { ...f, baselineStatus: compatibility.kind === "same-run-checkpoint" ? "checkpoint" : "persistent", baselineReason: migration ? `Reviewed identity migration: ${migration.reason} (${migration.reviewedBy}).` : "Matching semantic evidence and normalized location; producer display IDs are not identity." };
    }
    const candidates = priorTaxonomy.get(normalizeTaxonomy(f)) ?? [];
    const sourceNew = canClaim && eligible(f) && candidates.length === 0;
    const status = sourceNew ? "new" : compatibility.kind === "same-run-checkpoint" ? "checkpoint" : compatibility.kind === "tool-change" || compatibility.kind === "scope-change" || compatibility.kind === "incompatible" ? compatibility.kind : "unresolved";
    return { ...f, baselineStatus: status, baselineReason: sourceNew ? "Current actionable observation absent from the comparable prior scope." : candidates.length ? "Possible prior identity has changed evidence or location; explicit reviewed migration is required." : compatibility.limitations.join(" "), ...(candidates.length ? { lowConfidenceMatch: baseline[candidates[0]!]!.id } : {}) };
  });
  // A later exact match may consume a candidate. Only still-unmatched prior evidence can resolve.
  const resolved: Finding[] = [];
  const unresolved: Finding[] = [];
  baseline.forEach((f, i) => {
    if (matched.has(i)) return;
    const ambiguous = currentTaxonomy.has(normalizeTaxonomy(f));
    if (canClaim && eligible(f) && !ambiguous) resolved.push({ ...f, baselineStatus: "resolved", baselineReason: "Absent from the same complete scope with unchanged producer/schema versions at a later target revision." });
    else unresolved.push({ ...f, baselineStatus: "unresolved", baselineReason: ambiguous ? "Possible changed identity remains unresolved; absence is not a resolution." : compatibility.limitations.join(" ") });
  });
  const comparison: BaselineDiff["comparison"] = { ...compatibility,
    ...(options.priorContext ? { prior: options.priorContext } : {}), ...(options.currentContext ? { current: options.currentContext } : {}), migrations: validMigrations,
    denominators: { prior: baseline.length, current: current.length, matched: matchCount,
      comparablePrior: canClaim ? baseline.filter(eligible).length : 0, comparableCurrent: canClaim ? current.filter(eligible).length : 0,
      unresolvedPrior: unresolved.length, unresolvedCurrent: findings.length - matchCount - findings.filter((f) => f.baselineStatus === "new").length },
  };
  if (validMigrations.length !== migrationRows.length) comparison.limitations.push("Invalid or ambiguous migration mappings were not applied; mappings must bind one prior occurrence to one current occurrence with a reviewer and reason.");
  return { findings, resolved, unresolved, comparison, counts: { resolved: resolved.length, persistent: matchCount, new: findings.filter((f) => f.baselineStatus === "new").length } };
}

export function applyBaseline(doc: FindingsDocument, prior: Finding[] | FindingsDocument, priorLabel?: string, options: FindingIdentityOptions = {}): FindingsDocument {
  const baselineFindings = Array.isArray(prior) ? prior : prior.findings;
  const diff = diffAgainstBaseline(baselineFindings, doc.findings, { ...options,
    priorContext: options.priorContext ?? (Array.isArray(prior) ? undefined : prior.auditContext), currentContext: options.currentContext ?? doc.auditContext,
    migrations: options.migrations ?? doc.identityMigrations });
  return { ...doc, findings: diff.findings, baseline: { ...(priorLabel ? { priorLabel } : {}), resolved: diff.resolved, unresolved: diff.unresolved, comparison: diff.comparison, counts: diff.counts } };
}
