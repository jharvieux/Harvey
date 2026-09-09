// The calibration's current family is published and validated as one unit. Historical dynamic
// evidence is an explicitly retained INPUT, never a claim that this invocation ran a live probe.
import { createHash } from "node:crypto";
import { cpSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { buildDryRunScorecard } from "./cli/dry-run-scorecard.js";
import { validateFindings, type Finding, type FindingsDocument, type ValidationResult } from "./findings.js";
import type { DynamicScorecard } from "./pentest/scorecard.js";

const ARTIFACT_FILES = ["findings.json", "pii-data-map.json", "scorecard.json", "findings-report.json"] as const;
type ArtifactFile = typeof ARTIFACT_FILES[number];

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, v]) => [k, canonical(v)]));
  }
  return value;
}

function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
}

interface DryRunSource {
  target: string;
  /** Git tree of the retained scratch repository, including force-added secret fixtures. */
  targetTree: string;
}

interface RetainedDynamicInput {
  role: "historical-dynamic-evidence";
  sha256: string;
  document: DynamicScorecard;
}

interface Linkage {
  schemaVersion: 1;
  rawSha256: string;
  targetTree: string;
  dynamicSha256: string | null;
}

interface Receipt {
  schemaVersion: 1;
  canonicalization: "json-key-sorted-v1";
  producer: "src/cli/dry-run.ts";
  source: DryRunSource;
  retainedDynamic: RetainedDynamicInput | null;
  artifacts: Record<ArtifactFile, { sha256: string }>;
  transformations: {
    report: {
      kind: "findings-envelope-v1";
      reason: string;
      produced: number;
      delivered: number;
      deduped: number;
      suppressed: number;
      capped: number;
      notApplicable: number;
      synthesized: number;
    };
    scorecard: { kind: "calibration-scorecard-v1"; reason: string };
  };
}

export interface DryRunFamily {
  "findings.json": Finding[];
  "pii-data-map.json": unknown;
  "scorecard.json": ReturnType<typeof buildDryRunScorecard> & { artifactLinkage: Linkage };
  "findings-report.json": FindingsDocument & { artifactLinkage: Linkage };
  "artifact-family.json": Receipt;
}

/** Wrap the exact in-memory raw array. No dedupe, cap, suppression, or finding rewrite occurs here. */
export function buildDryRunFamily(findings: Finding[], dataMap: unknown, source: DryRunSource, dynamic?: DynamicScorecard): DryRunFamily {
  const raw = structuredClone(findings);
  const retainedDynamic: RetainedDynamicInput | null = dynamic
    ? { role: "historical-dynamic-evidence", sha256: digest(dynamic), document: structuredClone(dynamic) }
    : null;
  const artifactLinkage: Linkage = { schemaVersion: 1, rawSha256: digest(raw), targetTree: source.targetTree, dynamicSha256: retainedDynamic?.sha256 ?? null };
  const scorecard = { ...buildDryRunScorecard(raw, retainedDynamic?.document), artifactLinkage };
  const { summary } = scorecard;
  const plantedTotal = Object.values(summary).reduce((sum, n) => sum + n, 0);
  const report: DryRunFamily["findings-report.json"] = {
    meta: {
      client: "Calibration target (internal dry run — issue #34)",
      subtitle: "PARTIAL — mechanical scan + M1 detect-deeper only; no live DB/Docker in this pass",
      // Wall-clock time belongs in timing.json, not a deterministically regenerated artifact.
      date: "Undated calibration snapshot",
      commit: `Retained target tree ${source.targetTree}`,
      auditor: "Harvey dry-run harness (src/cli/dry-run.ts)",
      confidential: false,
      overallHealth: 0,
      tenantIsolation: "NOT ASSESSED IN THIS PASS — no live Supabase Advisor or manual/LLM policy-semantics pass ran in this invocation.",
      authModel: "N/A — not evaluated in this pass.",
      headline: `This is NOT a scored audit. It demonstrates the findings.json -> report render pipeline using real output from one partial scan. ${summary.asserted} of ${plantedTotal} planted bugs were asserted; ${summary["surfaced-for-review"]} were surfaced for review; ${summary.missed} missed; ${summary["requires-live-run"]} require a live run. ${retainedDynamic ? `M2 outcomes use historical evidence recorded ${retainedDynamic.document.generatedAt} against ${retainedDynamic.document.target}; this invocation ran no dynamic probes.` : "No historical M2 evidence was supplied; this invocation ran no dynamic probes."} See scorecard.json and artifact-family.json for the source linkage.`,
      scope: `${source.target} (mechanical scan; M1 detect-deeper grant/definer classifiers fed from the same retained migration SQL; M10 PII data map).`,
      methodology: "src/cli/dry-run.ts — findings are retained in full inside the report envelope; the scorecard is a separate classification of planted bugs, not a filtered finding set.",
      outOfScope: "Live DB, dynamic probes, built-bundle scanning, and the interactive semantic review were not executed by this invocation.",
    },
    findings: structuredClone(raw),
    artifactLinkage,
  };
  const artifacts = { "findings.json": raw, "pii-data-map.json": structuredClone(dataMap), "scorecard.json": scorecard, "findings-report.json": report };
  return {
    ...artifacts,
    "artifact-family.json": {
      schemaVersion: 1,
      canonicalization: "json-key-sorted-v1",
      producer: "src/cli/dry-run.ts",
      source: structuredClone(source),
      retainedDynamic,
      artifacts: Object.fromEntries(ARTIFACT_FILES.map((name) => [name, { sha256: digest(artifacts[name]) }])) as Receipt["artifacts"],
      transformations: {
        report: {
          kind: "findings-envelope-v1",
          reason: "Add report metadata and source linkage; preserve every raw finding occurrence and field. Rendering rollups remain downstream of this artifact seam.",
          produced: raw.length, delivered: report.findings.length, deduped: 0, suppressed: 0, capped: 0, notApplicable: 0, synthesized: 0,
        },
        scorecard: {
          kind: "calibration-scorecard-v1",
          reason: "Classify each planted bug against the gated corpus using this raw array and explicitly retained historical M2 evidence. This summary does not remove findings from the report.",
        },
      },
    },
  };
}

// Count OCCURRENCES, not just distinct ids: a duplicate must not hide a lost or invented row.
// Canonical JSON accepts formatting/key-order changes; the report envelope is classified above.
function findingDifference(raw: Finding[], derived: Finding[]) {
  const byId = (rows: Finding[]) => {
    const map = new Map<string, string[]>();
    for (const row of rows) map.set(row.id, [...(map.get(row.id) ?? []), digest(row)]);
    return map;
  };
  const before = byId(raw);
  const after = byId(derived);
  const rawOnly: string[] = [], derivedOnly: string[] = [], sameIdChanged: string[] = [];
  for (const id of new Set([...before.keys(), ...after.keys()])) {
    const a = [...(before.get(id) ?? [])], b = [...(after.get(id) ?? [])];
    const unmatched = a.filter((hash) => {
      const i = b.indexOf(hash);
      if (i < 0) return true;
      b.splice(i, 1);
      return false;
    });
    const changed = Math.min(unmatched.length, b.length);
    sameIdChanged.push(...Array<string>(changed).fill(id));
    rawOnly.push(...Array<string>(unmatched.length - changed).fill(id));
    derivedOnly.push(...Array<string>(b.length - changed).fill(id));
  }
  return { rawOnly, derivedOnly, sameIdChanged };
}

export function validateDryRunFamily(outDir: string): ValidationResult {
  const errors: string[] = [];
  const files: Record<string, unknown> = {};
  for (const name of [...ARTIFACT_FILES, "artifact-family.json"]) {
    try { files[name] = JSON.parse(readFileSync(join(outDir, name), "utf8")) as unknown; }
    catch (error) { errors.push(`${name}: cannot read complete artifact (${error instanceof Error ? error.message : String(error)})`); }
  }
  const raw = files["findings.json"];
  const report = files["findings-report.json"] as DryRunFamily["findings-report.json"] | undefined;
  const identifiable = (rows: unknown): rows is Finding[] => Array.isArray(rows) && rows.every((row: unknown) => typeof row === "object" && row !== null && "id" in row && typeof row.id === "string");
  let counts = "raw-only/derived-only/same-ID-changed counts unavailable (invalid or missing finding arrays)";
  if (identifiable(raw) && identifiable(report?.findings)) {
    const diff = findingDifference(raw as Finding[], report.findings);
    const summary = `raw-only=${diff.rawOnly.length}, derived-only=${diff.derivedOnly.length}, same-ID-changed=${diff.sameIdChanged.length}`;
    counts = summary;
    if (diff.rawOnly.length + diff.derivedOnly.length + diff.sameIdChanged.length > 0) {
      errors.push(`findings.json → findings-report.json: ${summary}. raw-only IDs: ${diff.rawOnly.slice(0, 10).join(", ") || "none"}; derived-only IDs: ${diff.derivedOnly.slice(0, 10).join(", ") || "none"}; same-ID-changed IDs: ${diff.sameIdChanged.slice(0, 10).join(", ") || "none"}`);
    }
  } else {
    errors.push("findings.json and findings-report.json must contain raw/derived finding arrays; raw-only/derived-only/same-ID-changed counts unavailable");
  }
  if (report) errors.push(...validateFindings(report).errors);
  const receipt = files["artifact-family.json"] as Receipt | undefined;
  if (receipt?.schemaVersion !== 1 || receipt.producer !== "src/cli/dry-run.ts" || !/^[a-f0-9]{40}$/.test(receipt.source?.targetTree ?? "") || typeof receipt.source?.target !== "string") {
    errors.push("artifact-family.json: expected a version-1 dry-run receipt with a retained target tree");
  } else if (Array.isArray(raw)) {
    try {
      const retained = receipt.retainedDynamic;
      if (retained !== null && (retained.role !== "historical-dynamic-evidence" || retained.sha256 !== digest(retained.document))) {
        errors.push("artifact-family.json: historical dynamic input does not match its retained digest/classification");
      }
      const expected = buildDryRunFamily(raw as Finding[], files["pii-data-map.json"], receipt.source, retained?.document);
      for (const name of ARTIFACT_FILES) {
        if (digest(files[name]) !== receipt.artifacts?.[name]?.sha256) errors.push(`${name}: content digest differs from artifact-family.json; files from different generations or a partial edit were mixed`);
      }
      // Recompute the actual transforms, including metadata and the scorecard join, to detect
      // stale coverage prose or a receipt that declares a fictitious drop.
      for (const name of ["scorecard.json", "findings-report.json", "artifact-family.json"] as const) {
        if (digest(files[name]) !== digest(expected[name])) errors.push(`${name}: source linkage or classified transformation differs from the retained raw findings/input snapshot`);
      }
    } catch (error) {
      errors.push(`artifact-family.json: invalid retained input (${error instanceof Error ? error.message : String(error)})`);
    }
  }
  if (errors.length > 0) errors.push(`Artifact comparison: ${counts}. Regenerate the entire family with pnpm exec tsx src/cli/dry-run.ts --out ${outDir}. If publication was interrupted, inspect ${join(dirname(resolve(outDir)), `.${basename(outDir)}.generation-lock`)} for the retained previous directory; never repair by copying a single artifact.`);
  return { ok: errors.length === 0, errors };
}

/** Directory activation: readers see a complete previous/new family or an absent current path.
 * A SIGKILL between renames leaves the previous directory under the lock for recovery. */
export function publishDryRunFamily(outDir: string, family: DryRunFamily, timing: unknown): void {
  const destination = resolve(outDir);
  const lock = join(dirname(destination), `.${basename(destination)}.generation-lock`);
  const staged = join(lock, "staged");
  const previous = join(lock, "previous");
  mkdirSync(dirname(destination), { recursive: true });
  if (existsSync(destination) && (!lstatSync(destination).isDirectory() || lstatSync(destination).isSymbolicLink())) throw new Error(`Dry-run output must be a real directory: ${destination}`);
  try { mkdirSync(lock); }
  catch { throw new Error(`Dry-run publication lock exists or cannot be created: ${lock}. Inspect its owner.json and retained previous/staged directories before retrying.`); }
  let movedPrevious = false, activated = false, restored = false;
  try {
    writeFileSync(join(lock, "owner.json"), JSON.stringify({ pid: process.pid, destination, staged, previous }));
    // Preserve scripts and historical evidence verbatim. They are not current-run outputs and
    // are deliberately absent from the generated-artifact manifest.
    if (existsSync(destination)) cpSync(destination, staged, { recursive: true, verbatimSymlinks: true });
    else mkdirSync(staged);
    for (const [name, value] of Object.entries(family)) {
      // A stale symlink in the output directory must not redirect an artifact write outside staging.
      rmSync(join(staged, name), { recursive: true, force: true });
      writeFileSync(join(staged, name), JSON.stringify(value, null, 2));
    }
    rmSync(join(staged, "timing.json"), { recursive: true, force: true });
    writeFileSync(join(staged, "timing.json"), JSON.stringify(timing, null, 2));
    const validation = validateDryRunFamily(staged);
    if (!validation.ok) throw new Error(validation.errors.join("\n"));
    if (existsSync(destination)) {
      renameSync(destination, previous);
      movedPrevious = true;
    }
    renameSync(staged, destination);
    activated = true;
  } catch (error) {
    if (movedPrevious && !existsSync(destination)) {
      try { renameSync(previous, destination); restored = true; }
      catch { throw new Error(`Dry-run activation and rollback failed. Current output is absent; recover the complete previous family from ${previous}. Original error: ${String(error)}`); }
    }
    throw error;
  } finally {
    if (!movedPrevious || activated || restored) rmSync(lock, { recursive: true, force: true });
  }
}
