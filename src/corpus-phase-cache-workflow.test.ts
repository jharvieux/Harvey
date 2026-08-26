import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { runInNewContext } from "node:vm";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "yaml";
import { rejectCorpusCacheTransport } from "./corpus-cache-transport.js";
import { semgrepPackReceipt, validateRestoredSemgrepPackArtifact } from "./corpus-mechanical-readiness.js";
import { readRecursiveSafe, statSafe } from "./fs-walk.js";
import { partitionTargets } from "./scan/corpus-shards.js";
import { EXTERNAL_CORPUS } from "./scan/external-corpus.js";
import { REGISTRY_PACKS, registryPackIdentity } from "./scan/semgrep.js";

const root = process.cwd();
const path = join(root, ".github", "workflows", "corpus-drift.yml");
const workflow = readFileSync(path, "utf8");
const mechanical = readFileSync(join(root, "src", "scan", "mechanical.ts"), "utf8");
const corpusCli = readFileSync(join(root, "src", "cli", "corpus-drift.ts"), "utf8");
const replayCli = readFileSync(join(root, "src", "cli", "replay-current-mechanical.ts"), "utf8");
const temporaryDirectories: string[] = [];

function transportWorkflowErrors(text: string, cli = corpusCli): string[] {
  const errors: string[] = [];
  if ((text.match(/Restore content-addressed corpus phase results — owner [1-4]/g) ?? []).length !== 4) errors.push("exact-run restore ownership");
  if ((text.match(/Restore trusted-main corpus phase results — owner [1-4]/g) ?? []).length !== 4) errors.push("trusted-main restore ownership");
  if ((text.match(/Save current-run corpus phase results for an exact retry — owner [1-4]/g) ?? []).length !== 4) errors.push("exact-run save ownership");
  if ((text.match(/Save successful main-shard corpus phase results — owner [1-4]/g) ?? []).length !== 4) errors.push("trusted-main save ownership");
  for (const namespace of [1, 2, 3, 4]) {
    if ((text.match(new RegExp(`path: \\.harvey-corpus-phase-cache/shard${namespace}`, "g")) ?? []).length !== 4) errors.push(`owner ${namespace} path`);
    if (!text.includes(`shard${namespace}-scope\${{ steps.phase-cache-scopes.outputs.scope${namespace} }}`)) errors.push(`owner ${namespace} scope`);
  }
  if (text.includes("corpus-phase-run-v5-") || text.includes("corpus-phase-main-v5-")) errors.push("legacy v5 fallback");
  if ((text.match(/github\.event_name == 'schedule' \|\| github\.event_name == 'workflow_dispatch'/g) ?? []).length < 12) errors.push("schedule four-owner activation");
  if (!/name: Upload drift scorecard\n\s+if: always\(\)/.test(text)) errors.push("scorecard failure delivery");
  if (!/name: Gate liveness — did this job actually score anything\?\n\s+if: always\(\)/.test(text)) errors.push("liveness failure delivery");
  if (!cli.includes("corpusCacheNamespaceForTarget") || (cli.match(/cacheDir: targetPhaseCacheDir/g) ?? []).length !== 6 || (cli.match(/cacheDir: targetPhaseCacheDir!/g) ?? []).length !== 1) errors.push("target owner routing");
  return errors;
}

afterEach(() => {
  for (const dir of temporaryDirectories.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function temporary(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(dir);
  return dir;
}

function seedSemgrepArtifact(dir: string, marker: string): string {
  const bodies = REGISTRY_PACKS.map((pack, ordinal) => ({ pack, body: `rules:\n  - id: ${marker}-${ordinal}\n    message: ${pack}\n` }));
  const identity = registryPackIdentity(bodies);
  const packDir = join(dir, "registry-packs", identity);
  mkdirSync(packDir, { recursive: true });
  const files = bodies.map(({ pack, body }, ordinal) => {
    const file = join(packDir, `${ordinal}-${pack.replaceAll("/", "-")}.yml`);
    writeFileSync(file, body);
    return file;
  });
  writeFileSync(join(dir, "registry-packs", "current.json"), `${JSON.stringify({ schema: 1, identity }, null, 2)}\n`);
  writeFileSync(join(dir, "receipt.json"), `${JSON.stringify(semgrepPackReceipt(files, identity), null, 2)}\n`);
  return identity;
}

interface ArtifactUploadStep {
  uses?: string;
  if?: string;
  with: { name: string; path: string; "include-hidden-files"?: boolean; "if-no-files-found"?: string };
}

function artifactUploads(text: string): ArtifactUploadStep[] {
  const document = parse(text) as { jobs: Record<string, { steps: ArtifactUploadStep[] }> };
  return Object.values(document.jobs).flatMap((job) => job.steps)
    .filter((step) => step.uses?.startsWith("actions/upload-artifact@"));
}

function hiddenPath(path: string): boolean {
  return path.split(/[\\/]/).some((segment) => segment.startsWith(".") && segment !== "." && segment !== "..");
}

/** Model upload-artifact's directory common-root stripping and download-by-name's direct restore. */
function artifactPayload(source: string, includeHiddenFiles: boolean): Map<string, Buffer> {
  // The uploader's globber prunes a hidden search root before it visits any descendants.
  if (!includeHiddenFiles && hiddenPath(source)) return new Map();
  return new Map(readRecursiveSafe(source)
    .filter((relative) => statSafe(join(source, relative))?.isFile())
    .filter((relative) => includeHiddenFiles || !relative.split("/").some((segment) => segment.startsWith(".")))
    .map((relative) => [relative, readFileSync(join(source, relative))]));
}

function downloadByName(payload: ReadonlyMap<string, Buffer>, destination: string): void {
  for (const [relative, body] of payload) {
    const file = join(destination, relative);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, body);
  }
}

function bytesDigest(files: readonly string[]): string {
  const hash = createHash("sha256");
  for (const file of files) hash.update(readFileSync(file));
  return hash.digest("hex");
}

interface WorkflowStep {
  id?: string;
  name?: string;
  if?: string;
  uses?: string;
  run?: string;
  env?: Record<string, string | number>;
  with?: Record<string, unknown>;
}

interface WorkflowJob {
  if?: string;
  "timeout-minutes"?: string | number;
  outputs?: Record<string, string>;
  strategy?: { matrix: { shard: string | number[] } };
  steps: WorkflowStep[];
}

interface WorkflowDocument { jobs: Record<string, WorkflowJob> }
const document = parse(workflow) as WorkflowDocument;
const liveSlugs = EXTERNAL_CORPUS.map((target) => target.slug).sort();
const events = ["push", "pull_request", "merge_group", "schedule", "workflow_dispatch"] as const;

function context(event: string, relevant = true, shard = 1) {
  const route = {
    relevant: String(relevant), "target-count": relevant ? String(liveSlugs.length) : "0",
    "target-slugs": JSON.stringify(relevant ? liveSlugs : []), scope: relevant ? "all pinned targets" : "nothing assessed",
  };
  return {
    github: { event_name: event, ref: "refs/heads/main", sha: "a".repeat(40), run_id: "123", run_attempt: "1", event: { repository: { default_branch: "main" } } },
    needs: {
      "prepare-current-inputs": { result: "success", outputs: route },
      shard: { result: "success" }, "current-replay": { result: event === "push" ? "success" : "skipped" },
    },
    steps: {
      score: { outcome: "success" }, targets: { outputs: { scope: "all" } }, merge: { outputs: { merged: "true" } },
      route: { outputs: route }, "phase-cache-scopes": { outcome: "success", outputs: Object.fromEntries([1, 2, 3, 4].map((n) => [`scope${n}`, `scope-${n}`])) },
      ...Object.fromEntries([1, 2, 3, 4].flatMap((n) => [
        [`phase-cache-${n}`, { outputs: { "cache-hit": "false", "cache-matched-key": "" } }],
        [`main-phase-cache-${n}`, { outputs: { "cache-matched-key": `trusted-${n}` } }],
      ])),
    } as Record<string, { outcome?: string; outputs?: Record<string, string> }>,
    inputs: { alert_drill: false, liveness_drill: false, force_cold_cache: false },
    matrix: { shard }, runner: { os: "Linux" }, status: "success",
  };
}
type Context = ReturnType<typeof context>;

// Evaluate the actual workflow's scalar-expression subset, not a second event router. Quoted
// strings stay opaque; dashed Actions property names are looked up as paths, not JS subtraction.
function expression(value: string | number | number[] | boolean, ctx: Context): unknown {
  if (typeof value !== "string") return value;
  const source = value.replace(/^\$\{\{\s*|\s*\}\}$/g, "").replace(
    /'(?:[^']|'')*'|\b(?:github|needs|steps|inputs|matrix|runner)(?:\.[A-Za-z_][A-Za-z0-9_-]*)+/g,
    (token) => token.startsWith("'") ? JSON.stringify(token.slice(1, -1).replaceAll("''", "'")) : `get(${JSON.stringify(token)})`,
  );
  return runInNewContext(source, {
    get: (path: string) => path.split(".").reduce<unknown>((value, key) => value && typeof value === "object" ? (value as Record<string, unknown>)[key] : undefined, ctx) ?? "",
    fromJSON: JSON.parse,
    format: (pattern: string, ...values: unknown[]) => pattern.replace(/\{(\d+)\}/g, (_, n: string) => String(values[Number(n)])),
    always: () => true, success: () => ctx.status === "success", failure: () => ctx.status === "failure", cancelled: () => ctx.status === "cancelled",
  }, { timeout: 1000 });
}

function active(step: { if?: string }, ctx: Context): boolean {
  const condition = step.if ?? "success()";
  // Actions applies an implicit success() unless the condition contains a status function.
  return (/\b(?:always|success|failure|cancelled)\(/.test(condition) || ctx.status === "success") && Boolean(expression(condition, ctx));
}

function render(value: string | number, ctx: Context): string {
  return String(value).replace(/\$\{\{([\s\S]*?)\}\}/g, (_, source: string) => String(expression(source, ctx)));
}

function named(doc: WorkflowDocument, job: string, name: string): WorkflowStep {
  const found = doc.jobs[job]?.steps.find((step) => step.name === name);
  if (!found) throw new Error(`missing ${job} step: ${name}`);
  return found;
}

function shell(step: WorkflowStep, ctx: Context, options: { dir?: string; env?: Record<string, string>; prelude?: string } = {}) {
  if (!step.run) throw new Error(`missing shipping shell: ${step.name}`);
  const dir = options.dir ?? temporary("corpus-workflow-shell-");
  const output = join(dir, "github-output");
  const result = spawnSync("bash", ["-c", `${options.prelude ?? ""}\n${render(step.run, ctx)}`], {
    cwd: dir, encoding: "utf8", timeout: 10_000,
    env: { ...process.env, GITHUB_OUTPUT: output, ...Object.fromEntries(Object.entries(step.env ?? {}).map(([key, value]) => [key, render(value, ctx)])), ...options.env },
  });
  expect(result.error).toBeUndefined();
  return { ...result, dir, output: statSafe(output) ? readFileSync(output, "utf8") : "" };
}

function assertTopology(doc: WorkflowDocument, event: string, relevant = true, executeTransport = false): void {
  const ctx = context(event, relevant);
  const sharded = ["push", "pull_request", "merge_group"].includes(event);
  const shardJob = doc.jobs.shard!;
  const matrix = expression(shardJob.strategy!.matrix.shard, ctx);
  expect(matrix).toEqual(sharded ? [1, 2, 3, 4] : [1]);
  expect(active(shardJob, ctx)).toBe(relevant);
  const score = named(doc, "shard", "Score the corpus against its baselines");
  expect(expression(score.env!.SHARD_COUNT!, ctx)).toBe(sharded ? 4 : 1);
  expect(expression(score.env!.HARVEY_CURRENT_MECHANICAL_READINESS!, ctx)).toBe(event === "push" ? "1" : "0");
  const upload = named(doc, "shard", "Upload drift scorecard");
  const artifactNames: string[] = [];
  for (const shard of active(shardJob, ctx) ? matrix as number[] : []) {
    ctx.matrix.shard = shard;
    const owners = sharded ? [shard] : [1, 2, 3, 4];
    const selectedTargets = sharded ? partitionTargets(liveSlugs, 4)[shard - 1]! : liveSlugs;
    expect(expression(shardJob["timeout-minutes"]!, ctx), `${event}/${shard}: cold Carbon budget`)
      .toBe(sharded && selectedTargets.includes("carbon") ? 45 : 30);
    expect(active(score, ctx)).toBe(true);
    expect(expression(score.env!.SHARD!, ctx)).toBe(shard);
    expect(active(upload, ctx)).toBe(true);
    artifactNames.push(render(String(upload.with!.name), ctx));
    expect(artifactNames.at(-1)).toBe(sharded ? `corpus-drift-scorecard-part-${shard}` : "corpus-drift-scorecard");
    for (const n of [1, 2, 3, 4]) {
      const own = owners.includes(n);
      for (const [name, expected] of [
        [`Restore content-addressed corpus phase results — owner ${n}`, own],
        [`Restore trusted-main corpus phase results — owner ${n}`, own],
        [`Save current-run corpus phase results for an exact retry — owner ${n}`, own && event !== "push"],
        [`Save successful main-shard corpus phase results — owner ${n}`, own && event === "push"],
      ] as const) {
        const step = named(doc, "shard", name);
        expect(active(step, ctx), `${event}/${shard}: ${name}`).toBe(expected);
        expect(step.with!.path).toBe(`.harvey-corpus-phase-cache/shard${n}`);
        expect(render(String(step.with!.key), ctx)).toContain(`-shard${n}-scopescope-${n}-`);
      }
      ctx.steps[`phase-cache-${n}`]!.outputs!["cache-hit"] = "true";
      expect(active(named(doc, "shard", `Restore trusted-main corpus phase results — owner ${n}`), ctx)).toBe(false);
      ctx.steps[`phase-cache-${n}`]!.outputs!["cache-hit"] = "false";
    }
    for (const verb of ["Validate", "Record"]) {
      const step = named(doc, "shard", `${verb} corpus phase-cache transport provenance`);
      expect(active(step, ctx)).toBe(true);
      if (executeTransport) {
        const dir = temporary("corpus-transport-routing-");
        const calls = join(dir, "calls");
        const result = shell(step, ctx, { dir, env: { CALLS: calls }, prelude: 'pnpm() { printf "%s\\n" "$*" >> "$CALLS"; }' });
        expect(result.status, result.stderr).toBe(0);
        const commands = readFileSync(calls, "utf8").trim().split("\n");
        expect(commands.map((line) => Number(/--namespace (\d+)/.exec(line)?.[1]))).toEqual(owners);
        for (const [index, line] of commands.entries()) {
          expect(line).toContain(`--dir .harvey-corpus-phase-cache/shard${owners[index]}`);
          expect(line).toContain(`--event ${event}`);
          expect(line).toContain(verb === "Record" ? `--family ${event === "push" ? "main" : "run"}` : `--matched-key trusted-${owners[index]}`);
        }
      }
    }
    if (executeTransport) {
      const dir = temporary("corpus-score-routing-");
      const calls = join(dir, "calls");
      const targetScope = shell(named(doc, "shard", "Declare the complete target population"), ctx);
      expect(targetScope.status).toBe(0);
      expect(targetScope.output).toBe("scope=all\n");
      const scored = shell(score, ctx, { dir, env: { CALLS: calls }, prelude: 'pnpm() { printf "%s\\n" "$*" >> "$CALLS"; }' });
      expect(scored.status, scored.stderr).toBe(0);
      expect(readFileSync(calls, "utf8").trim()).toBe(`corpus-drift --install --shard ${shard}/${sharded ? 4 : 1} --json corpus-drift${sharded ? `-shard${shard}` : ""}.json`);
    }
  }
  expect(new Set(artifactNames).size).toBe(artifactNames.length);
  expect(active(doc.jobs["current-replay"]!, ctx)).toBe(event === "push");
  expect(doc.jobs["current-replay"]!.strategy!.matrix.shard).toEqual([1, 2, 3, 4]);
  expect(named(doc, "current-replay", "Execute the independent exact-head replay").env!.SHARD_COUNT).toBe(4);
  for (const name of ["Collect the shard scorecards", "Merge the shard scorecards into corpus-drift.json"]) {
    expect(active(named(doc, "drift", name), ctx), name).toBe(relevant && sharded);
  }
  expect(named(doc, "drift", "Collect the shard scorecards").with).toMatchObject({ pattern: "corpus-drift-scorecard-part-*", "merge-multiple": true, path: "parts" });
  expect(active(named(doc, "drift", "Collect the independent replay parts"), ctx)).toBe(event === "push");
  const mergeIndex = doc.jobs.drift!.steps.findIndex((step) => step.id === "merge");
  const setup = doc.jobs.drift!.steps.slice(mergeIndex + 1, mergeIndex + 5);
  expect(setup.map((step) => step.uses ?? step.run)).toEqual(["actions/checkout@v4", "pnpm/action-setup@v4", "actions/setup-node@v4", "pnpm install --frozen-lockfile"]);
  const readiness = named(doc, "drift", "Current registry producer ↔ independent replay equivalence/readiness");
  for (const step of [...setup, readiness]) {
    expect(active(step, ctx)).toBe(event === "push");
    const unmerged = structuredClone(ctx);
    unmerged.steps.merge!.outputs!.merged = "false";
    expect(active(step, unmerged)).toBe(false);
  }
  const mergedUpload = named(doc, "drift", "Upload the merged drift scorecard");
  expect(mergedUpload.with).toMatchObject({ name: "corpus-drift-scorecard", "if-no-files-found": "error" });
  expect(active(mergedUpload, ctx)).toBe(true);
  ctx.steps.merge!.outputs!.merged = "false";
  expect(active(mergedUpload, ctx)).toBe(false);
}

function unresolvedStepReferences(doc: WorkflowDocument): string[] {
  return Object.entries(doc.jobs).flatMap(([jobName, job]) => {
    const ids = new Set(job.steps.map((step) => step.id).filter(Boolean));
    return [...JSON.stringify(job).matchAll(/\bsteps\.([A-Za-z_][A-Za-z0-9_-]*)\./g)]
      .filter((ref) => !ids.has(ref[1])).map((ref) => `${jobName}: steps.${ref[1]}`);
  });
}

interface Scorecard {
  rows: { slug: string; check: string; pass: boolean; detail: string }[];
  findings: Record<string, unknown[]>;
  detectors: Record<string, unknown>;
  mechanicalContexts: Record<string, unknown>;
}

function scorecardParts(): Record<string, Scorecard> {
  return Object.fromEntries(partitionTargets(liveSlugs, 4).map((slugs, index) => [`corpus-drift-shard${index + 1}.json`, {
    rows: slugs.flatMap((slug) => [
      { slug, check: "M1 baseline", pass: true, detail: `count unchanged: ${slug}` },
      { slug, check: "M8 baseline", pass: false, detail: `counted drift: ${slug}` },
    ]),
    findings: Object.fromEntries(slugs.map((slug, n) => [slug, n % 2 ? [] : [{ id: `${slug}-finding`, sourceModule: "M8", location: { file: "src/example.ts", startLine: 7 }, evidence: { snippet: "uncovered branch" } }]])),
    detectors: Object.fromEntries(slugs.map((slug) => [slug, [{ detector: "fixture-producer", status: "ran", unitsExamined: 9, scope: `${slug} source` }]])),
    mechanicalContexts: Object.fromEntries(slugs.map((slug) => [slug, { target: slug, contentDigest: `${slug}-digest`, execution: { preparedRoot: `/prepared/${slug}`, unchanged: true } }])),
  }]));
}

function runMerge(parts: Record<string, unknown>, expected = JSON.stringify(liveSlugs), run?: string) {
  const dir = temporary("corpus-scorecard-merge-");
  mkdirSync(join(dir, "parts"));
  for (const [file, body] of Object.entries(parts)) writeFileSync(join(dir, "parts", file), typeof body === "string" ? body : JSON.stringify(body));
  const step = named(document, "drift", "Merge the shard scorecards into corpus-drift.json");
  return shell({ ...step, run: run ?? step.run }, context("pull_request"), { dir, env: { EXPECTED_TARGET_SLUGS: expected } });
}

function assertRejectedMerge(result: ReturnType<typeof runMerge>): void {
  expect(result.status, result.stdout + result.stderr).not.toBeNull();
  expect(result.status, result.stdout + result.stderr).not.toBe(0);
  expect(result.output).not.toContain("merged=true");
  expect(statSafe(join(result.dir, "corpus-drift.json"))).toBeUndefined();
}

function assertCompleteMerge(parts: Record<string, Scorecard>, run?: string): void {
  const result = runMerge(parts, JSON.stringify(liveSlugs), run);
  expect(result.status, result.stderr).toBe(0);
  expect(result.output).toBe("merged=true\n");
  const merged = JSON.parse(readFileSync(join(result.dir, "corpus-drift.json"), "utf8")) as Scorecard;
  expect(merged).toEqual({
    rows: Object.values(parts).flatMap((part) => part.rows),
    findings: Object.assign({}, ...Object.values(parts).map((part) => part.findings)),
    detectors: Object.assign({}, ...Object.values(parts).map((part) => part.detectors)),
    mechanicalContexts: Object.assign({}, ...Object.values(parts).map((part) => part.mechanicalContexts)),
  });
  expect(Object.keys(merged.findings).sort()).toEqual(liveSlugs);
}

describe("#1870 actual corpus workflow event and artifact topology", () => {
  it.each(events)("binds %s scorers, every transport owner, artifacts, merge and replay to the shipping expressions", (event) => {
    assertTopology(document, event, true, true);
  });

  it.each([...events.map((event) => [event, "full-scan"]), ["pull_request", "declared-no-op"], ["merge_group", "declared-no-op"]])("threads live target slugs through the actual %s/%s route shell and merge environment", (event, decision) => {
    const ctx = context(event!);
    const dir = temporary("corpus-route-output-");
    const ownership = join(dir, "ownership-fixture.json");
    const receipt = join(dir, "receipt-fixture.json");
    writeFileSync(ownership, JSON.stringify({ consumers: [{ targetSelection: { targets: [...liveSlugs].reverse() } }] }));
    writeFileSync(receipt, JSON.stringify({ decision, closureDigest: "closure-fixture" }));
    const result = shell(named(document, "prepare-current-inputs", "Generate live corpus ownership and classify the exact Git range"), ctx, {
      dir, env: { RUNNER_TEMP: dir, GITHUB_WORKSPACE: dir, PR_BASE_SHA: "b".repeat(40), MERGE_GROUP_BASE_SHA: "c".repeat(40), OWNERSHIP_FIXTURE: ownership, RECEIPT_FIXTURE: receipt },
      prelude: 'pnpm() { case "$4" in ownership) cp "$OWNERSHIP_FIXTURE" "${@: -1}" ;; classify) cp "$RECEIPT_FIXTURE" "${@: -1}" ;; *) return 99 ;; esac; }',
    });
    expect(result.status, result.stderr).toBe(0);
    const outputs = Object.fromEntries(result.output.trim().split("\n").map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
    ctx.steps.route!.outputs = outputs;
    const selected = decision === "declared-no-op" ? [] : liveSlugs;
    expect(outputs["target-count"]).toBe(String(selected.length));
    expect(outputs.relevant).toBe(String(selected.length > 0));
    if (!selected.length) expect(outputs.scope).toContain("nothing assessed");
    const wired = expression(document.jobs["prepare-current-inputs"]!.outputs!["target-slugs"]!, ctx);
    expect(JSON.parse(String(wired))).toEqual(selected);
    ctx.needs["prepare-current-inputs"].outputs["target-slugs"] = String(wired);
    const merge = named(document, "drift", "Merge the shard scorecards into corpus-drift.json");
    expect(JSON.parse(render(merge.env!.EXPECTED_TARGET_SLUGS!, ctx))).toEqual(selected);
  });

  it.each(["pull_request", "merge_group"])("allocates no scorer/cache and records only nothing-assessed for a proven %s no-op", (event) => {
    const ctx = context(event, false);
    assertTopology(document, event, false);
    expect(active(document.jobs.drift!, ctx)).toBe(true);
    expect(active(named(document, "drift", "Declare the proven-disjoint no-op"), ctx)).toBe(true);
    expect(named(document, "drift", "Declare the proven-disjoint no-op").with).toMatchObject({ status: "declared-no-op" });
    expect(active(named(document, "drift", "Record the measured full-population outcome"), ctx)).toBe(false);
    for (const step of document.jobs.shard!.steps.filter((step) => step.uses?.startsWith("actions/cache/"))) expect(active(step, ctx)).toBe(false);
    for (const verb of ["Validate", "Record"]) expect(active(named(document, "shard", `${verb} corpus phase-cache transport provenance`), ctx)).toBe(false);
  });

  it.each(["failure", "cancelled", "skipped"])("keeps the aggregate fail-closed for %s preparation, scoring and push replay", (result) => {
    for (const event of events) {
      const ctx = context(event);
      ctx.needs["prepare-current-inputs"].result = result;
      expect(active(document.jobs.shard!, ctx)).toBe(false);
      expect(active(document.jobs["current-replay"]!, ctx)).toBe(false);
      expect(active(document.jobs.drift!, ctx)).toBe(true);
      const preparation = named(document, "drift", "Shared preparation and relevance classification must have succeeded");
      expect(shell(preparation, ctx).status).toBe(1);
      ctx.needs["prepare-current-inputs"].result = "success";
      ctx.needs.shard.result = result;
      const required = named(document, "drift", "Every required corpus execution must have succeeded");
      expect(shell(required, ctx).status).toBe(1);
      ctx.needs.shard.result = "success";
      ctx.needs["current-replay"].result = result;
      expect(shell(required, ctx).status).toBe(event === "push" ? 1 : 0);
      ctx.status = "failure";
      expect(active(named(document, "drift", "Record the measured full-population outcome"), ctx)).toBe(false);
      expect(active(named(document, "drift", "Gate liveness — did this required context declare its outcome?"), ctx)).toBe(true);
      ctx.steps.score!.outcome = result;
      for (const step of document.jobs.shard!.steps.filter((step) => step.uses === "actions/cache/save@v4" || step.name === "Record corpus phase-cache transport provenance")) expect(active(step, ctx)).toBe(false);
      expect(active(named(document, "shard", "Upload drift scorecard"), ctx)).toBe(true);
      expect(active(named(document, "shard", "Gate liveness — did this job actually score anything?"), ctx)).toBe(true);
    }
  });

  it("preserves distinct manual liveness and alert drills without invoking an alert action", () => {
    for (const drill of ["liveness_drill", "alert_drill"] as const) {
      const ctx = context("workflow_dispatch");
      ctx.inputs[drill] = true;
      if (drill === "alert_drill") {
        const alertStep = document.jobs.shard!.steps.find((step) => step.if === "inputs.alert_drill")!;
        expect(active(alertStep, ctx)).toBe(true);
        expect(shell(alertStep, ctx).status).toBe(1);
        ctx.status = "failure";
      }
      expect(active(named(document, "shard", "Score the corpus against its baselines"), ctx)).toBe(false);
      for (const step of document.jobs.shard!.steps.filter((step) => step.uses === "actions/cache/save@v4" || step.name === "Record corpus phase-cache transport provenance")) expect(active(step, ctx)).toBe(false);
      expect(active(named(document, "shard", "Gate liveness — did this job actually score anything?"), ctx)).toBe(drill === "liveness_drill");
      ctx.status = "failure";
      expect(active(named(document, "shard", "Open or update the drift tracking issue"), ctx)).toBe(drill === "alert_drill");
    }
  });

  it("resolves every steps reference within its own job and catches deletion of the existing targets id", () => {
    expect(unresolvedStepReferences(document)).toEqual([]);
    const changed = structuredClone(document);
    const targetStep = changed.jobs.shard!.steps.find((step) => step.id === "targets")!;
    expect(targetStep).toBeDefined();
    delete targetStep.id;
    expect(unresolvedStepReferences(changed)).toContain("shard: steps.targets");
    expect(() => expect(unresolvedStepReferences(changed)).toEqual([])).toThrow();
  });

  it("merges all four live partitions without losing rows, findings, detectors or mechanical contexts", () => {
    assertCompleteMerge(scorecardParts());
  });

  it.each([1, 2, 3, 4])("rejects missing part %i before publishing anything", (n) => {
    const parts = scorecardParts();
    delete parts[`corpus-drift-shard${n}.json`];
    assertRejectedMerge(runMerge(parts));
  });

  it.each(["corpus-drift-shard0.json", "corpus-drift-shard5.json", "corpus-drift-shard01.json"])("rejects extra part %s before publishing anything", (file) => {
    const parts = scorecardParts();
    parts[file] = parts["corpus-drift-shard1.json"]!;
    assertRejectedMerge(runMerge(parts));
  });

  it.each(["duplicate", "unknown", "missing"])("rejects a %s target even when each part's four fields agree", (mode) => {
    const parts = scorecardParts();
    const part = parts["corpus-drift-shard2.json"]!;
    const slug = Object.keys(part.findings)[0]!;
    const replacement = mode === "duplicate" ? Object.keys(parts["corpus-drift-shard1.json"]!.findings)[0]! : "not-a-live-target";
    part.rows = part.rows.flatMap((row) => row.slug !== slug ? [row] : mode === "missing" ? [] : [{ ...row, slug: replacement }]);
    for (const map of [part.findings, part.detectors, part.mechanicalContexts]) {
      if (mode !== "missing") map[replacement] = map[slug]!;
      delete map[slug];
    }
    assertRejectedMerge(runMerge(parts));
  });

  it.each([
    ["rows", []], ["rows", {}], ["rows", null], ["rows", [{ check: "missing slug" }]],
    ["findings", {}], ["findings", []], ["findings", null],
    ["detectors", {}], ["detectors", []], ["detectors", null],
    ["mechanicalContexts", {}], ["mechanicalContexts", []], ["mechanicalContexts", null],
  ])("rejects malformed or empty %s=%j", (field, value) => {
    const parts = scorecardParts();
    const file = "corpus-drift-shard1.json";
    assertRejectedMerge(runMerge({ ...parts, [file]: { ...parts[file], [String(field)]: value } }));
  });

  it.each(["rows", "findings", "detectors", "mechanicalContexts"] as const)("rejects loss of one target from %s", (field) => {
    const parts = scorecardParts();
    const part = parts["corpus-drift-shard2.json"]!;
    const slug = Object.keys(part.findings)[0]!;
    if (field === "rows") part.rows = part.rows.filter((row) => row.slug !== slug);
    else delete part[field][slug];
    assertRejectedMerge(runMerge(parts));
  });

  it("rejects malformed JSON and a non-array per-target findings payload", () => {
    const parts = scorecardParts();
    const file = "corpus-drift-shard1.json";
    assertRejectedMerge(runMerge({ ...parts, [file]: "{invalid json" }));
    const slug = Object.keys(parts[file]!.findings)[0]!;
    assertRejectedMerge(runMerge({ ...parts, [file]: { ...parts[file], findings: { [slug]: {} } } }));
  });

  it.each(["[]", "null", "{}", '[""]', "[42]", "not-json", JSON.stringify([...liveSlugs, liveSlugs[0]]), JSON.stringify([...liveSlugs.slice(1), "unknown-target"])])("rejects invalid expected target population %s", (expected) => {
    assertRejectedMerge(runMerge(scorecardParts(), expected));
  });

  // Mutate only disposable parsed YAML / extracted shell. These are the same assertions used
  // above: each independent reversion must make the positive production contract go red.
  it.each(["pull_request", "merge_group"])("detects independent matrix and count regressions for %s", (event) => {
    for (const field of ["matrix", "count"]) {
      const changed = structuredClone(document);
      const removeEvent = (value: string) => value.replace(` || github.event_name == '${event}'`, "");
      if (field === "matrix") changed.jobs.shard!.strategy!.matrix.shard = removeEvent(String(changed.jobs.shard!.strategy!.matrix.shard));
      else {
        const score = named(changed, "shard", "Score the corpus against its baselines");
        score.env!.SHARD_COUNT = removeEvent(String(score.env!.SHARD_COUNT));
      }
      expect(() => assertTopology(changed, event)).toThrow();
    }
  });

  it.each([
    "Restore content-addressed corpus phase results — owner 4",
    "Restore trusted-main corpus phase results — owner 4",
    "Save current-run corpus phase results for an exact retry — owner 4",
    "Validate corpus phase-cache transport provenance",
    "Record corpus phase-cache transport provenance",
  ])("detects lost schedule/manual owner activation in %s", (name) => {
    const changed = structuredClone(document);
    const step = named(changed, "shard", name);
    if (step.run) step.run = step.run.split("\n").filter((line) => !line.includes("= schedule")).join("\n");
    else step.if = step.if!.replaceAll(" || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'", "");
    expect(step).not.toEqual(named(document, "shard", name));
    for (const event of ["schedule", "workflow_dispatch"]) expect(() => assertTopology(changed, event, true, true)).toThrow();
  });

  it("detects a trusted-main save spilling across owner namespaces", () => {
    const changed = structuredClone(document);
    const step = named(changed, "shard", "Save successful main-shard corpus phase results — owner 4");
    step.if = step.if!.replace("matrix.shard == 4", "true");
    expect(() => assertTopology(changed, "push")).toThrow();
  });

  it.each(["Upload drift scorecard", "Collect the shard scorecards", "Merge the shard scorecards into corpus-drift.json"])("detects independent PR/queue part routing loss at %s", (name) => {
    const changed = structuredClone(document);
    const step = named(changed, name === "Upload drift scorecard" ? "shard" : "drift", name);
    if (name === "Upload drift scorecard") step.with!.name = String(step.with!.name).replace(" || github.event_name == 'pull_request' || github.event_name == 'merge_group'", "");
    else step.if = step.if!.replace(" || github.event_name == 'pull_request' || github.event_name == 'merge_group'", "");
    for (const event of ["pull_request", "merge_group"]) expect(() => assertTopology(changed, event)).toThrow();
  });

  it("detects readiness setup accidentally expanding to PR/queue", () => {
    const changed = structuredClone(document);
    const setup = changed.jobs.drift!.steps.find((step) => step.with?.path === "source")!;
    setup.if = setup.if!.replace(" && github.event_name == 'push'", "");
    for (const event of ["pull_request", "merge_group"]) expect(() => assertTopology(changed, event)).toThrow();
  });

  it("goes red when the exact-part guard is removed even with the complete live population", () => {
    const parts = scorecardParts();
    parts["corpus-drift-shard0.json"] = parts["corpus-drift-shard1.json"]!;
    delete parts["corpus-drift-shard1.json"];
    const run = named(document, "drift", "Merge the shard scorecards into corpus-drift.json").run!;
    const changed = run.replace(/if \[ "\$\{#parts\[@\]\}" -ne 4 \][\s\S]*?\nfi\n/, "");
    expect(changed).not.toBe(run);
    assertRejectedMerge(runMerge(parts));
    const unguarded = runMerge(parts, JSON.stringify(liveSlugs), changed);
    expect(unguarded.status, unguarded.stderr).toBe(0);
    expect(() => assertRejectedMerge(unguarded)).toThrow();
  });

  it("goes red when the exact-population guard is removed", () => {
    const parts = scorecardParts();
    const part = parts["corpus-drift-shard2.json"]!;
    const slug = Object.keys(part.findings)[0]!;
    part.rows = part.rows.filter((row) => row.slug !== slug);
    for (const map of [part.findings, part.detectors, part.mechanicalContexts]) delete map[slug];
    const run = named(document, "drift", "Merge the shard scorecards into corpus-drift.json").run!;
    const changed = run.replace(/^jq -e -s[\s\S]*?\n\}\n/m, "");
    expect(changed).not.toBe(run);
    assertRejectedMerge(runMerge(parts));
    const unguarded = runMerge(parts, JSON.stringify(liveSlugs), changed);
    expect(unguarded.status, unguarded.stderr).toBe(0);
    expect(() => assertRejectedMerge(unguarded)).toThrow();
  });

  it("goes red if the population union silently deduplicates a target scored twice", () => {
    const parts = scorecardParts();
    const from = parts["corpus-drift-shard1.json"]!;
    const into = parts["corpus-drift-shard2.json"]!;
    const slug = Object.keys(from.findings)[0]!;
    into.rows.push(...from.rows);
    for (const field of ["findings", "detectors", "mechanicalContexts"] as const) into[field][slug] = from[field][slug]!;
    const run = named(document, "drift", "Merge the shard scorecards into corpus-drift.json").run!;
    const changed = run.replace("([.[].findings | keys[]] | sort)", "([.[].findings | keys[]] | unique)");
    expect(changed).not.toBe(run);
    assertRejectedMerge(runMerge(parts));
    const deduplicated = runMerge(parts, JSON.stringify(liveSlugs), changed);
    expect(deduplicated.status, deduplicated.stderr).toBe(0);
    expect(() => assertRejectedMerge(deduplicated)).toThrow();
  });

  it.each(["detectors", "mechanicalContexts"])("goes red if the merger loses %s values", (field) => {
    const run = named(document, "drift", "Merge the shard scorecards into corpus-drift.json").run!;
    const changed = run.replace(`(map(.${field}) | add)`, "{}");
    expect(changed).not.toBe(run);
    expect(() => assertCompleteMerge(scorecardParts(), changed)).toThrow();
  });
});

describe("#1864 corpus phase-cache workflow contract", () => {
  it("satisfies the complete ownership-bound transport contract", () => {
    expect(transportWorkflowErrors(workflow)).toEqual([]);
  });

  it.each([
    ["v5 key fallback", workflow.replace("corpus-phase-run-v6-", "corpus-phase-run-v5-")],
    ["missing owner restore", workflow.replace("Restore content-addressed corpus phase results — owner 4", "Restore content-addressed corpus phase results — missing")],
    ["shared parent path", workflow.replace("path: .harvey-corpus-phase-cache/shard3", "path: .harvey-corpus-phase-cache")],
    ["scheduled single transport", workflow.replaceAll(" || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'", "")],
    ["scorecard success-only", workflow.replace("name: Upload drift scorecard\n        if: always()", "name: Upload drift scorecard\n        if: success()")],
  ] as const)("turns red under the disposable %s workflow reversion", (_name, reverted) => {
    expect(transportWorkflowErrors(reverted)).not.toEqual([]);
  });

  it("turns red if target cache writes are routed back to the shared parent", () => {
    const revertedCli = corpusCli.replaceAll("cacheDir: targetPhaseCacheDir", "cacheDir: phaseCacheDir");
    expect(transportWorkflowErrors(workflow, revertedCli)).toContain("target owner routing");
  });
  it("keeps the required context reporting while PR and merge-group relevance may declare a no-op", () => {
    expect(workflow).toMatch(/^\s{2}pull_request:\s*$/m);
    expect(workflow).toMatch(/^\s{2}merge_group:\s*$/m);
    expect(workflow).toContain("fail-fast: false");
    expect(workflow).toMatch(/drift:\n\s+name: clone\s+pinned\s+commits\s+\+\s+score\s+baselines\n\s+needs: \[prepare-current-inputs, shard, current-replay\]\n\s+if: always\(\)/);
    expect(workflow).toContain(`if [ "$result" != "success" ]`);
    expect(workflow).not.toContain("prepare-current-inputs:\n    if: github.event_name != 'pull_request' && github.event_name != 'merge_group'");
    expect(workflow).toContain("if: needs.prepare-current-inputs.result == 'success' && needs.prepare-current-inputs.outputs.relevant == 'true'");
    expect(workflow).toContain("name: Generate live corpus ownership and classify the exact Git range");
    expect(workflow).toContain("name: Declare the proven-disjoint no-op");
    expect(workflow).toContain("Gate liveness — did this required context declare its outcome?");
    expect(workflow).toContain("nothing assessed; exact Git change is disjoint from immutable closure");
    for (const event of ["pull_request", "merge_group"]) assertTopology(document, event, false);
    expect(workflow).toContain("if: needs.prepare-current-inputs.result == 'success' && github.event_name == 'push'");
  });

  it("restores and saves the content-addressed directory without making a cache miss fatal or clean", () => {
    expect(workflow.match(/uses: actions\/cache\/restore@v4/g)).toHaveLength(8);
    expect(workflow.match(/uses: actions\/cache\/save@v4/g)).toHaveLength(8);
    expect(workflow.match(/path: \.harvey-corpus-phase-cache\/shard[1-4]/g)).toHaveLength(16);
    for (const namespace of [1, 2, 3, 4]) {
      expect(workflow.match(new RegExp(`path: \\.harvey-corpus-phase-cache/shard${namespace}`, "g"))).toHaveLength(4);
      expect(workflow).toContain(`shard${namespace}-scope\${{ steps.phase-cache-scopes.outputs.scope${namespace} }}`);
    }
    expect(workflow).toContain("HARVEY_CORPUS_PHASE_CACHE_DIR: .harvey-corpus-phase-cache");
    expect(workflow).not.toMatch(/Restore content-addressed corpus phase results[\s\S]{0,300}continue-on-error/);
    expect(workflow).not.toContain("corpus-phase-run-v5-");
    expect(workflow).not.toContain("corpus-phase-main-v5-");
    expect(workflow).toContain("src/cli/corpus-cache-transport.ts scopes >> \"$GITHUB_OUTPUT\"");
    expect(workflow).toContain("Validate corpus phase-cache transport provenance");
    expect(workflow).toContain("Record corpus phase-cache transport provenance");
    expect(workflow).toContain("steps.phase-cache-4.outputs.cache-matched-key || steps.main-phase-cache-4.outputs.cache-matched-key");
    expect(workflow).toContain('--dir ".harvey-corpus-phase-cache/shard$namespace"');
    expect(workflow).toContain("--head-sha '${{ github.sha }}'");
    expect(workflow).toContain("--platform '${{ runner.os }}'");
    expect(workflow).toContain("--family '${{ github.event_name == 'push' && 'main' || 'run' }}'");
    expect(workflow).toContain('--namespace "$namespace"');
    expect(workflow).toContain("CORPUS CACHE OWNER $namespace SIZE:");
  });

  it("runs and seeds the full corpus after merge while preserving unconditional PR reporting", () => {
    expect(workflow).toMatch(/push:\n\s+branches: \[main\]/);
    expect(workflow).toContain("--default-ref 'refs/heads/${{ github.event.repository.default_branch }}'");
    expect(workflow).toContain("--event '${{ github.event_name }}'");
    expect(workflow).toContain("--ref '${{ github.ref }}'");
    assertTopology(document, "push");
    expect(workflow).toContain("if: needs.prepare-current-inputs.result == 'success' && github.event_name == 'push'");
    expect(workflow).toContain("if: steps.merge.outputs.merged == 'true' && github.event_name == 'push'");
    expect(workflow.match(/Save successful main-shard corpus phase results — owner [1-4]/g)).toHaveLength(4);
    expect(workflow).toContain("key: corpus-phase-main-v6-${{ runner.os }}-shard4-scope${{ steps.phase-cache-scopes.outputs.scope4 }}-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.sha }}");
    expect(workflow).not.toContain("Save shard2 main-visible corpus phase results");
    expect(workflow).not.toContain("Save shard3 main-visible corpus phase results");
    expect(workflow).toContain("success() && steps.score.outcome == 'success'");
    expect(workflow).not.toMatch(/Save successful main-shard corpus phase results[\s\S]{0,250}if: always\(\)/);
    expect(workflow.match(/github\.ref == format\('refs\/heads\/\{0\}', github\.event\.repository\.default_branch\) && matrix\.shard == [1-4]/g)).toHaveLength(4);
  });

  it("keeps schedule/manual to one scorer while activating all four canonical transports", () => {
    expect(workflow).toContain("scheduled/manual leg touches all four");
    expect((workflow.match(/github\.event_name == 'schedule' \|\| github\.event_name == 'workflow_dispatch'/g) ?? []).length).toBeGreaterThanOrEqual(12);
    expect(workflow).toContain("&& 4 || 1");
    expect(workflow).toContain('pnpm corpus-drift --install --shard "$SHARD/$SHARD_COUNT"');
    expect(workflow).toContain("|| 'corpus-drift-scorecard'");
    expect(workflow).toContain("mode: save");
    expect(corpusCli).toContain("corpusCacheNamespaceForTarget");
    expect(corpusCli).toContain("targetPhaseCacheDir");
    expect(corpusCli).toContain("cacheDir: targetPhaseCacheDir");
  });

  it("keeps scorecard and liveness delivery fail-closed after transport failure", () => {
    expect(workflow).toMatch(/name: Upload drift scorecard\n\s+if: always\(\)/);
    expect(workflow).toMatch(/name: Gate liveness — did this job actually score anything\?\n\s+if: always\(\)/);
    expect(workflow).toContain(`if [ "$result" != "success" ]`);
    expect(workflow).toContain("if-no-files-found: warn");
  });

  it("materializes one exact Semgrep input and makes every producer and replay reuse it", () => {
    expect(workflow).toContain("name: Materialize the one current Semgrep registry input");
    expect(workflow).toContain("name: current-mechanical-semgrep-pack");
    expect(workflow.match(/name: Restore the run's exact shared Semgrep bytes/g)).toHaveLength(2);
    expect(workflow.match(/name: Validate the exact shared Semgrep artifact layout/g)).toHaveLength(2);
    expect(workflow.match(/path: \.harvey-current-semgrep/g)).toHaveLength(3);
    expect(artifactUploads(workflow).find((step) => step.with.name === "current-mechanical-semgrep-pack")?.with["include-hidden-files"]).toBe(true);
    expect(workflow).toContain("HARVEY_SEMGREP_REGISTRY_SNAPSHOT_DIR: .harvey-current-semgrep");
    expect(workflow).not.toContain("path: .harvey-current-replay-cache");
    expect(workflow).toContain("HARVEY_SEMGREP_REGISTRY_SNAPSHOT_MODE: reuse");
    expect(corpusCli).toContain("registryPackIdentity: sharedRegistry");
    expect(corpusCli).toContain("validateRestoredSemgrepPackArtifact(registrySnapshotDir!)");
    expect(corpusCli).toContain("resolve(registrySnapshotDir) === resolve(phaseCacheDir)");
    expect(replayCli).toContain("validateRestoredSemgrepPackArtifact(registryDir)");
  });

  it("opts every hidden artifact search root into the uploader's file selection", () => {
    const hiddenUploads = artifactUploads(workflow).filter((step) => step.with.path.split(/\r?\n/).some(hiddenPath));
    expect(hiddenUploads.length).toBeGreaterThan(0);
    for (const step of hiddenUploads) {
      expect(step.with["include-hidden-files"], step.with.name).toBe(true);
    }
  });

  it("retains the relevance ownership and no-op receipt through their exact production upload step", () => {
    const uploads = artifactUploads(workflow).filter((step) => step.with.name === "corpus-drift-relevance");
    expect(uploads).toHaveLength(1);
    const upload = uploads[0];
    if (!upload) throw new Error("relevance artifact upload step is absent");
    expect(upload.if).toBe("github.event_name == 'pull_request' || github.event_name == 'merge_group'");
    expect(upload.with.path).toBe(".harvey-corpus-relevance");
    expect(upload.with["if-no-files-found"]).toBe("error");
    const source = join(temporary("relevance-artifact-roundtrip-"), upload.with.path);
    mkdirSync(source);
    writeFileSync(join(source, "ownership.json"), '{"schema":1}\n');
    writeFileSync(join(source, "receipt.json"), '{"decision":"declared-no-op","assessment":{"status":"nothing-assessed","unitsAssessed":0}}\n');

    const payload = artifactPayload(source, upload.with["include-hidden-files"] === true);
    expect([...payload.keys()].sort()).toEqual(["ownership.json", "receipt.json"]);
    // The production omission returns no files, even though neither child's basename is hidden.
    expect(artifactPayload(source, false).size).toBe(0);
  });

  it("reconstructs upload → download-by-name for both consumers with one identical canonical pack", () => {
    const source = join(temporary("semgrep-artifact-roundtrip-"), ".harvey-current-semgrep");
    const producer = join(temporary("semgrep-producer-"), ".harvey-current-semgrep");
    const replay = join(temporary("semgrep-replay-"), ".harvey-current-semgrep");
    const identity = seedSemgrepArtifact(source, "one-run");
    const payload = artifactPayload(source, true);

    expect(payload.has("registry-packs/current.json")).toBe(true);
    expect(payload.has("receipt.json")).toBe(true);
    expect([...payload.keys()].some((name) => name.startsWith(".harvey-current-semgrep/"))).toBe(false);
    downloadByName(payload, producer);
    downloadByName(payload, replay);

    const producerPack = validateRestoredSemgrepPackArtifact(producer);
    const replayPack = validateRestoredSemgrepPackArtifact(replay);
    expect(producerPack.identity).toBe(identity);
    expect(replayPack.identity).toBe(identity);
    expect(bytesDigest(producerPack.files)).toBe(bytesDigest(replayPack.files));
    expect(producerPack.receipt).toEqual(replayPack.receipt);
  });

  it("fails loud on nested, missing, mixed, or hidden upload payloads", () => {
    const source = temporary("semgrep-artifact-falsifiers-");
    seedSemgrepArtifact(source, "canonical");
    writeFileSync(join(source, ".partial-upload"), "must not disappear silently\n");
    const withHidden = artifactPayload(source, true);
    const withoutHidden = artifactPayload(source, false);
    expect(withHidden.has(".partial-upload")).toBe(true);
    expect(withoutHidden.has(".partial-upload")).toBe(false);

    const hidden = join(temporary("semgrep-hidden-"), ".harvey-current-semgrep");
    downloadByName(withHidden, hidden);
    expect(() => validateRestoredSemgrepPackArtifact(hidden)).toThrow(/inventory is mixed or nested/);

    const nested = join(temporary("semgrep-nested-"), ".harvey-current-semgrep");
    downloadByName(withoutHidden, join(nested, "current-mechanical-semgrep-pack"));
    expect(() => validateRestoredSemgrepPackArtifact(nested)).toThrow(/current\.json is missing/);

    const missing = join(temporary("semgrep-missing-"), ".harvey-current-semgrep");
    downloadByName(withoutHidden, missing);
    rmSync(join(missing, "registry-packs", "current.json"));
    expect(() => validateRestoredSemgrepPackArtifact(missing)).toThrow(/current\.json is missing/);

    const mixed = join(temporary("semgrep-mixed-"), ".harvey-current-semgrep");
    const other = join(temporary("semgrep-other-"), ".harvey-current-semgrep");
    downloadByName(withoutHidden, mixed);
    seedSemgrepArtifact(other, "different-run");
    copyFileSync(join(other, "receipt.json"), join(mixed, "receipt.json"));
    expect(() => validateRestoredSemgrepPackArtifact(mixed)).toThrow(/disagree with receipt\.json/);
  });

  it("keeps immutable registry bytes intact when a rejected mutable phase transport is cleared", () => {
    const job = temporary("semgrep-separated-transport-");
    const registry = join(job, ".harvey-current-semgrep");
    const phaseCache = join(job, ".harvey-corpus-phase-cache");
    seedSemgrepArtifact(registry, "immutable");
    mkdirSync(phaseCache);
    writeFileSync(join(phaseCache, "untrusted-phase.json"), "{}\n");

    rejectCorpusCacheTransport(phaseCache);

    expect(readRecursiveSafe(phaseCache)).toEqual([]);
    expect(() => validateRestoredSemgrepPackArtifact(registry)).not.toThrow();
  });

  it("keeps daily provider validation warm and exposes an explicit cold-equivalence drill", () => {
    expect(workflow).toContain("force_cold_cache:");
    expect(workflow).toContain('if [ "${{ inputs.force_cold_cache }}" = "true" ]');
    expect(workflow).not.toContain('if [ "${{ github.event_name }}" = "schedule" ] || [ "${{ github.event_name }}" = "workflow_dispatch" ]');
    expect(workflow).toContain("cold_flag=(--force-cold-cache)");
    expect(workflow.match(/"\$\{cold_flag\[@\]\}"/g)).toHaveLength(1);
    expect(mechanical).toContain("assertMechanicalCacheVerification(phases, opts.phaseCache)");
  });

  it("uses the shipping executable closure rather than a path approximation or blanket event no-op", () => {
    expect(workflow).not.toContain("git diff --name-only '${{ github.event.pull_request.base.sha }}' HEAD");
    expect(workflow).not.toContain("*) relevant=true ;;");
    expect(workflow).not.toContain("Route third-party corpus execution by event");
    expect(workflow.match(/corpus-drift-relevance\.ts ownership/g)).toHaveLength(1);
    expect(workflow.match(/corpus-drift-relevance\.ts classify/g)).toHaveLength(1);
    expect(workflow).toContain('--root "$GITHUB_WORKSPACE"');
    expect(workflow).toContain('--base "$base"');
    expect(workflow).toContain('--head "$HEAD_SHA"');
    expect(workflow).toContain('if [ "$EVENT_NAME" = pull_request ] || [ "$EVENT_NAME" = merge_group ]');
    expect(workflow).toContain("decision=unconditional-full");
    expect(workflow).toContain('if [ "$decision" = full-scan ]');
  });
});
