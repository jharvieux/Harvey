import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { CORPUS_SCANNER_ENTRY_POINTS } from "../corpus-scanner-cache.js";
import { readRecursiveSafe, statSafe } from "../fs-walk.js";
import {
  discoverImplementationClosure,
  type ImplementationClosureEdge,
  type ImplementationClosureUncertainty,
} from "./implementation-closure.js";

type CorpusInputCategory =
  | "producer"
  | "helper"
  | "rules"
  | "config"
  | "schema"
  | "taxonomy"
  | "manifest"
  | "baseline"
  | "ledger"
  | "workflow"
  | "action"
  | "tools"
  | "package"
  | "lock"
  | "runtime"
  | "external-state";

export interface CorpusInputReceipt {
  category: CorpusInputCategory;
  path: string;
  digest: string;
  consumer: string;
}

export interface CorpusClosureReceipt {
  schema: 1;
  revision: string;
  roots: string[];
  inputs: CorpusInputReceipt[];
  edges: Array<ImplementationClosureEdge & { from: string; to: string }>;
  uncertainties: Array<ImplementationClosureUncertainty & { path: string }>;
  inventory: string[];
  digest: string;
}

export interface CorpusChangedPath {
  status: string;
  path: string;
  oldPath?: string;
}

interface CorpusRelevanceDecision {
  schema: 1;
  base: CorpusClosureReceipt;
  head: CorpusClosureReceipt;
  changed: CorpusChangedPath[];
  relevant: boolean;
  verdict: "full-scan" | "declared-no-op";
  reasons: string[];
  matched: Array<{ path: string; status: string; consumers: CorpusInputReceipt[] }>;
  disjoint: string[];
  uncertainties: Array<{ revision: string; kind: string; path: string; detail: string }>;
}

const CORPUS_ENTRY_POINTS: readonly string[] = [
  "src/cli/corpus-drift.ts",
  // The decision and evidence consumers are part of the gate they control. If one of these moves,
  // the old closure must not declare the scorer/relevance change a no-op merely because the
  // scanner producers themselves were untouched.
  "src/cli/corpus-relevance.ts",
  "src/cli/corpus-relevance-history.ts",
  "src/cli/corpus-benchmark.ts",
  "src/cli/corpus-benchmark-sample.ts",
  "src/corpus-checkin-sample.ts",
  "src/cli/corpus-checkin-sample.ts",
  "src/cli/replay-current-mechanical.ts",
  "src/cli/materialize-current-semgrep.ts",
  "src/cli/corpus-pins.ts",
  "src/cli/corpus-cache-transport.ts",
  "src/cli/validate-current-mechanical-readiness.ts",
  ...Object.values(CORPUS_SCANNER_ENTRY_POINTS),
];

const WORKFLOW = ".github/workflows/corpus-drift.yml";
const CORPUS_ADVISORY_SNAPSHOT_DIR = "src/scan/__fixtures__/corpus-advisories/";

interface ExplicitInput {
  category: Exclude<CorpusInputCategory, "producer" | "helper" | "tools" | "action">;
  consumer: string;
  select: (path: string) => boolean;
}

// Non-import inputs have one registry. Everything imported by an executable is discovered by the
// shared implementation graph; these are files consumed through filesystem/tool/workflow APIs.
const CORPUS_NON_IMPORT_INPUTS: readonly ExplicitInput[] = [
  { category: "rules", consumer: "mechanical Semgrep/gitleaks rule loaders", select: (path) => path.startsWith("src/scan/rules/") },
  { category: "config", consumer: "quality/static scanner configuration", select: (path) => [".jscpd.json", "knip.json", "knip.production.json", "tsconfig.json"].includes(path) },
  { category: "schema", consumer: "normalized Finding validation and scorecard serialization", select: (path) => path === "src/findings.ts" },
  { category: "taxonomy", consumer: "module matching and baseline scoring", select: (path) => path === "src/findings.ts" || path === "src/cwe-map.ts" },
  { category: "manifest", consumer: "pinned corpus target enumeration", select: (path) => path === "src/scan/external-corpus.ts" },
  { category: "baseline", consumer: "per-target corpus score expectations", select: (path) => path === "src/scan/external-corpus.ts" },
  { category: "ledger", consumer: "audit-coverage module initialization reached by quick-scan corpus scoring", select: (path) => path === "audit-execution-log.json" },
  { category: "external-state", consumer: "loadCorpusAdvisorySnapshot for corpus drift and current-mechanical replay", select: (path) => path.startsWith(CORPUS_ADVISORY_SNAPSHOT_DIR) },
  { category: "workflow", consumer: "required corpus-drift execution", select: (path) => path === WORKFLOW },
  { category: "package", consumer: "pnpm script and JavaScript dependency identity", select: (path) => path === "package.json" },
  { category: "package", consumer: "pnpm workspace topology and install configuration for corpus execution", select: (path) => path === "pnpm-workspace.yaml" },
  { category: "package", consumer: "pnpm workspace dependency identity for corpus execution", select: (path) => path === "site/package.json" },
  { category: "lock", consumer: "resolved JavaScript toolchain identity", select: (path) => path === "pnpm-lock.yaml" },
  { category: "runtime", consumer: "Actions Node runtime selection", select: (path) => path === ".nvmrc" },
] as const;

function sha256(body: string | Buffer): string {
  return createHash("sha256").update(body).digest("hex");
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function normalize(root: string, path: string): string {
  return relative(root, path).replaceAll("\\", "/");
}

function discoverLocalActionFiles(root: string): string[] {
  const workflowPath = join(root, WORKFLOW);
  if (!existsSync(workflowPath)) return [];
  const actionRoots = new Set<string>();
  const inspect = (path: string): void => {
    const text = readFileSync(path, "utf8");
    for (const match of text.matchAll(/uses:\s*["']?\.\/(\.github\/actions\/[A-Za-z0-9_./-]+)/g)) {
      const actionRoot = match[1]!.replace(/\/$/, "");
      if (actionRoots.has(actionRoot)) continue;
      actionRoots.add(actionRoot);
      for (const manifest of ["action.yml", "action.yaml"]) {
        const nested = join(root, actionRoot, manifest);
        if (existsSync(nested)) inspect(nested);
      }
    }
  };
  inspect(workflowPath);
  const inventory = readRecursiveSafe(root);
  return inventory.filter((path) => statSafe(join(root, path))?.isFile()
    && [...actionRoots].some((actionRoot) => path.startsWith(`${actionRoot}/`)));
}

function receipt(category: CorpusInputCategory, path: string, root: string, consumer: string): CorpusInputReceipt {
  return { category, path, digest: sha256(readFileSync(join(root, path))), consumer };
}

export function discoverCorpusClosure(root: string, revision: string): CorpusClosureReceipt {
  const inventory = readRecursiveSafe(root)
    .filter((path) => statSafe(join(root, path))?.isFile())
    .sort();
  const roots = CORPUS_ENTRY_POINTS.map((path) => join(root, path));
  const implementation = discoverImplementationClosure(roots);
  const inputs: CorpusInputReceipt[] = [];
  const rootSet = new Set(CORPUS_ENTRY_POINTS);
  for (const absolute of implementation.files) {
    const path = normalize(root, absolute);
    const category: CorpusInputCategory = path.startsWith("tools/")
      ? "tools"
      : rootSet.has(path)
        ? "producer"
        : "helper";
    inputs.push(receipt(category, path, root, category === "producer" ? "corpus executable entry point" : "transitive corpus implementation"));
  }
  for (const registration of CORPUS_NON_IMPORT_INPUTS) {
    for (const path of inventory.filter(registration.select)) inputs.push(receipt(registration.category, path, root, registration.consumer));
  }
  for (const path of discoverLocalActionFiles(root)) inputs.push(receipt("action", path, root, `local action reached from ${WORKFLOW}`));

  const canonicalInputs = inputs.sort((a, b) => `${a.path}\0${a.category}\0${a.consumer}`.localeCompare(`${b.path}\0${b.category}\0${b.consumer}`));
  const edges = implementation.edges.map((edge) => ({ ...edge, from: normalize(root, edge.from), to: normalize(root, edge.to) }));
  const uncertainties = implementation.uncertainties.map((item) => ({ ...item, path: normalize(root, item.path) }));
  const digest = sha256(stable({ roots: [...CORPUS_ENTRY_POINTS], inputs: canonicalInputs, edges, uncertainties }));
  return { schema: 1, revision, roots: [...CORPUS_ENTRY_POINTS], inputs: canonicalInputs, edges, uncertainties, inventory, digest };
}

export function decideCorpusRelevance(
  base: CorpusClosureReceipt,
  head: CorpusClosureReceipt,
  changed: readonly CorpusChangedPath[],
): CorpusRelevanceDecision {
  const byPath = new Map<string, CorpusInputReceipt[]>();
  for (const input of [...base.inputs, ...head.inputs]) {
    const values = byPath.get(input.path) ?? [];
    if (!values.some((value) => value.category === input.category && value.digest === input.digest && value.consumer === input.consumer)) values.push(input);
    byPath.set(input.path, values);
  }
  const known = new Set([...base.inventory, ...head.inventory]);
  const matched: CorpusRelevanceDecision["matched"] = [];
  const disjoint: string[] = [];
  const reasons: string[] = [];
  const uncertainties = [
    ...base.uncertainties.map((item) => ({ revision: base.revision, ...item })),
    ...head.uncertainties.map((item) => ({ revision: head.revision, ...item })),
  ];

  if (uncertainties.length > 0) reasons.push(`implementation closure has ${uncertainties.length} unresolved/dynamic/unreadable discovery edge(s)`);
  for (const change of changed) {
    const paths = [...new Set([change.path, change.oldPath].filter((path): path is string => Boolean(path)))];
    const consumers = paths.flatMap((path) => byPath.get(path) ?? []);
    if (consumers.length > 0) {
      matched.push({ path: change.path, status: change.status, consumers });
      reasons.push(`${change.status} ${change.path} reaches ${[...new Set(consumers.map((input) => `${input.category}:${input.consumer}`))].join(", ")}`);
    } else if (change.status.startsWith("A") || change.status.startsWith("C")) {
      reasons.push(`${change.status} ${change.path} is a newly added, unregistered path that cannot be proved disjoint from the corpus closure`);
    } else if (paths.some((path) => !known.has(path))) {
      reasons.push(`${change.status} ${change.path} is absent from both discovered revisions and cannot be proved disjoint`);
    } else {
      disjoint.push(change.path);
    }
  }
  if (changed.length === 0) reasons.push("the changed-path population is empty or unreadable");
  const relevant = reasons.length > 0;
  if (!relevant) reasons.push(`${disjoint.length} changed path(s) are disjoint from base ${base.digest.slice(0, 12)} and head ${head.digest.slice(0, 12)} closures`);
  return {
    schema: 1,
    base,
    head,
    changed: [...changed],
    relevant,
    verdict: relevant ? "full-scan" : "declared-no-op",
    reasons,
    matched,
    disjoint: disjoint.sort(),
    uncertainties,
  };
}
