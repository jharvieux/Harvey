import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { performance } from "node:perf_hooks";
import {
  buildImportGraph,
  collectPathAliases,
} from "../detectors/app-router.js";
import {
  parseFresh,
  readonlySourceFile,
  withSourceParseCache,
  type CachedSourceFile,
  type SourceInput,
} from "../detectors/common.js";
import {
  CONFIG_FILE,
  EXCLUDED_DIR,
  isGeneratedSource,
  SOURCE_FILE,
} from "../detectors/load-sources.js";
import { readRecursiveSafe, statSafe } from "../fs-walk.js";
import { collectWorkspaceManifests } from "../workspaces.js";
import { resolvedTree } from "./dependencies.js";
import { detectTargetFramework, type TargetFramework } from "./framework-detect.js";

const WALK_SOURCE = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const SQL_FILE = /\.sql$/;
const PRISMA_SCHEMA = /(^|\/)schema\.prisma$/;
const SNAPSHOT_SCHEMA = /^(schema\.sql|supabase\/schema\.sql|db\/schema\.sql)$/;
const ORDERED_MIGRATION_ROOTS = ["supabase/migrations/", "prisma/migrations/", "migrations/"] as const;
const CONTEXT_IDENTITY_FILE = /(^|\/)(?:package\.json|pnpm-workspace\.yaml|pnpm-lock\.yaml|package-lock\.json|yarn\.lock|bun\.lockb?|npm-shrinkwrap\.json)$/;

interface SchemaInventory {
  orderedMigrations: readonly { file: string; sql: string }[];
  snapshots: readonly { file: string; sql: string }[];
  prisma: readonly { file: string; schema: string }[];
}

export interface MechanicalContextMetrics {
  filesPresent: number;
  filesRead: number;
  filesParsed: number;
  astsBuilt: number;
  astCacheHits: number;
  importGraphNodes: number;
  importGraphEdges: number;
  inventoryBuildMs: number;
  astBuildMs: number;
  importGraphBuildMs: number;
  aggregateRunnerMs: number;
  criticalPathMs: number;
  legacyEquivalentFileReads: number;
  avoidedFileReads: number;
}

type MutableMetrics = MechanicalContextMetrics;

interface MechanicalContextIdentity {
  root: string;
  contentDigest: string;
  lifetime: "one-mechanical-scan";
  invalidation: "dispose-after-scan-or-content-digest-change";
}

function frozenSource(path: string, text: string): SourceInput {
  return Object.freeze({ path, text });
}

function readonlyMap<K, V>(entries: Iterable<readonly [K, V]>): ReadonlyMap<K, V> {
  const target = new Map(entries);
  return Object.freeze(new Proxy(target, {
    get(map, property) {
      if (property === "set" || property === "delete" || property === "clear") {
        return () => { throw new TypeError("mechanical scan context maps are immutable"); };
      }
      const value = Reflect.get(map, property, map) as unknown;
      return typeof value === "function" ? value.bind(map) : value;
    },
  }));
}

function immutable<T>(value: T): T {
  if (Array.isArray(value)) return Object.freeze(value.map((entry) => immutable(entry))) as T;
  if (value instanceof Map) {
    return readonlyMap([...value].map(([key, entry]) => [immutable(key), immutable(entry)] as const)) as T;
  }
  if (value && typeof value === "object") {
    return Object.freeze(Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, immutable(entry)]))) as T;
  }
  return value;
}

function hasExcludedSegment(path: string): boolean {
  return path.split("/").slice(0, -1).some((part) => EXCLUDED_DIR.test(part));
}

function digest(files: readonly SourceInput[]): string {
  const hash = createHash("sha256");
  for (const file of [...files].sort((a, b) => a.path.localeCompare(b.path))) {
    hash.update(String(file.path.length));
    hash.update("\0");
    hash.update(file.path);
    hash.update(String(file.text.length));
    hash.update("\0");
    hash.update(file.text);
  }
  return hash.digest("hex");
}

function migrationOrder(path: string): number {
  const root = ORDERED_MIGRATION_ROOTS.findIndex((candidate) => path.startsWith(candidate));
  return root < 0 ? Number.MAX_SAFE_INTEGER : root;
}

export class MechanicalScanContext {
  readonly identity: MechanicalContextIdentity;
  readonly sourceFiles: readonly SourceInput[];
  /** Full load-sources extension surface for detectors whose legacy walker included .mts/.cts. */
  readonly envSourceFiles: readonly SourceInput[];
  readonly loadedSources: readonly SourceInput[];
  readonly sourceAndRootManifest: readonly SourceInput[];
  readonly serviceRoleSources: readonly SourceInput[];
  readonly workspace: ReturnType<typeof collectWorkspaceManifests>;
  readonly dependencyTree: ReturnType<typeof resolvedTree>;
  readonly schemas: SchemaInventory;
  readonly framework: TargetFramework;
  readonly paths: readonly string[];
  readonly pathAliases: ReturnType<typeof collectPathAliases>;

  readonly #metrics: MutableMetrics;
  readonly #toolResults = new Map<string, unknown>();
  #asts?: ReadonlyMap<string, { text: string; statements: readonly { kind: number; pos: number; end: number }[] }>;
  #parseCache?: ReadonlyMap<string, CachedSourceFile>;
  #importGraph?: ReadonlyMap<string, readonly string[]>;
  #disposed = false;

  constructor(root: string) {
    const started = performance.now();
    const paths = readRecursiveSafe(root);
    this.paths = Object.freeze([...paths]);
    const inventory: SourceInput[] = [];
    const identityInputs: SourceInput[] = [];
    for (const path of paths) {
      if (!statSafe(join(root, path))?.isFile()) continue;
      const name = basename(path);
      if (CONTEXT_IDENTITY_FILE.test(path)) identityInputs.push(frozenSource(path, readFileSync(join(root, path), "utf8")));
      if (!WALK_SOURCE.test(name) && !SOURCE_FILE.test(name) && !CONFIG_FILE.test(name) && !SQL_FILE.test(name) && !PRISMA_SCHEMA.test(path)) continue;
      inventory.push(frozenSource(path, readFileSync(join(root, path), "utf8")));
    }
    Object.freeze(inventory);
    this.sourceFiles = Object.freeze(inventory.filter((file) => WALK_SOURCE.test(basename(file.path)) && !file.path.split("/").some((part) => ["node_modules", ".git", ".next", "dist", "build", "coverage"].includes(part))));
    this.envSourceFiles = Object.freeze(inventory.filter((file) => SOURCE_FILE.test(basename(file.path)) && !file.path.split("/").some((part) => ["node_modules", ".git", ".next", "dist", "build", "coverage"].includes(part))));
    this.loadedSources = Object.freeze(inventory.filter((file) => {
      const name = basename(file.path);
      if (hasExcludedSegment(file.path) || (!SOURCE_FILE.test(name) && !CONFIG_FILE.test(name))) return false;
      return CONFIG_FILE.test(name) || !isGeneratedSource(name, file.text);
    }));
    const rootManifest = inventory.find((file) => file.path === "package.json");
    this.sourceAndRootManifest = Object.freeze(rootManifest ? [...this.sourceFiles, rootManifest] : [...this.sourceFiles]);
    this.serviceRoleSources = Object.freeze(inventory.filter((file) => WALK_SOURCE.test(basename(file.path)) || /^(tsconfig|jsconfig)\.json$/.test(basename(file.path))));
    this.workspace = immutable(collectWorkspaceManifests(root));
    const dependencyTree = resolvedTree(root);
    this.dependencyTree = dependencyTree ? Object.freeze({ source: dependencyTree.source, versions: readonlyMap(dependencyTree.versions) }) : undefined;
    this.framework = detectTargetFramework(root);
    this.pathAliases = immutable(collectPathAliases([...this.loadedSources]));
    const orderedMigrations = inventory
      .filter((file) => SQL_FILE.test(file.path) && migrationOrder(file.path) < Number.MAX_SAFE_INTEGER)
      .map((file) => Object.freeze({ file: file.path, sql: file.text }))
      .sort((a, b) => migrationOrder(a.file) - migrationOrder(b.file) || a.file.localeCompare(b.file));
    const snapshots = inventory.filter((file) => SNAPSHOT_SCHEMA.test(file.path)).map((file) => Object.freeze({ file: file.path, sql: file.text }));
    const prisma = inventory.filter((file) => PRISMA_SCHEMA.test(file.path)).map((file) => Object.freeze({ file: file.path, schema: file.text }));
    this.schemas = Object.freeze({ orderedMigrations: Object.freeze(orderedMigrations), snapshots: Object.freeze(snapshots), prisma: Object.freeze(prisma) });
    this.identity = Object.freeze({
      root,
      contentDigest: digest([...inventory, ...identityInputs.filter((candidate) => !inventory.some((file) => file.path === candidate.path))]),
      lifetime: "one-mechanical-scan",
      invalidation: "dispose-after-scan-or-content-digest-change",
    });
    this.#metrics = {
      filesPresent: paths.length,
      filesRead: inventory.length,
      filesParsed: 0,
      astsBuilt: 0,
      astCacheHits: 0,
      importGraphNodes: 0,
      importGraphEdges: 0,
      inventoryBuildMs: performance.now() - started,
      astBuildMs: 0,
      importGraphBuildMs: 0,
      aggregateRunnerMs: 0,
      criticalPathMs: 0,
      legacyEquivalentFileReads: 0,
      avoidedFileReads: 0,
    };
  }

  get asts(): ReadonlyMap<string, { text: string; statements: readonly { kind: number; pos: number; end: number }[] }> {
    this.#assertLive();
    if (!this.#asts) {
      const started = performance.now();
      const cache = new Map<string, CachedSourceFile>();
      const snapshots = new Map<string, { text: string; statements: readonly { kind: number; pos: number; end: number }[] }>();
      for (const file of this.envSourceFiles) {
        const sourceFile = readonlySourceFile(parseFresh(file.path, file.text));
        cache.set(file.path, {
          text: file.text,
          sourceFile,
          onHit: () => { this.#metrics.astCacheHits += 1; },
        });
        Object.freeze(cache.get(file.path));
        snapshots.set(file.path, Object.freeze({
          text: file.text,
          statements: Object.freeze(Array.from(sourceFile.statements, (statement) => Object.freeze({ kind: statement.kind, pos: statement.pos, end: statement.end }))),
        }));
      }
      this.#parseCache = readonlyMap(cache);
      this.#asts = readonlyMap(snapshots);
      this.#metrics.filesParsed = cache.size;
      this.#metrics.astsBuilt = cache.size;
      this.#metrics.astBuildMs = performance.now() - started;
    }
    return this.#asts;
  }

  get importGraph(): ReadonlyMap<string, readonly string[]> {
    this.#assertLive();
    if (!this.#importGraph) {
      const started = performance.now();
      void this.asts;
      const sources = new Map([...this.#parseCache!].map(([path, entry]) => [path, entry.sourceFile]));
      const graph = buildImportGraph(sources, new Set(sources.keys()), [...this.pathAliases]);
      this.#importGraph = readonlyMap([...graph].map(([path, edges]) => [path, Object.freeze([...edges])] as const));
      this.#metrics.importGraphNodes = graph.size;
      this.#metrics.importGraphEdges = [...graph.values()].reduce((sum, edges) => sum + edges.length, 0);
      this.#metrics.importGraphBuildMs = performance.now() - started;
    }
    return this.#importGraph;
  }

  withAstCache<T>(run: () => T): T {
    this.#assertLive();
    void this.asts;
    return withSourceParseCache(this.#parseCache!, run);
  }

  recordToolResult(name: string, value: unknown): void {
    this.#assertLive();
    if (this.#toolResults.has(name)) throw new Error(`tool result ${name} was recorded twice in one scan context`);
    this.#toolResults.set(name, immutable(value));
  }

  toolResult<T>(name: string): T | undefined {
    this.#assertLive();
    return this.#toolResults.get(name) as T | undefined;
  }

  recordDetectorRun(durationMs: number, legacyEquivalentFileReads: number): void {
    this.#assertLive();
    this.#metrics.aggregateRunnerMs += durationMs;
    this.#metrics.criticalPathMs = Math.max(this.#metrics.criticalPathMs, durationMs);
    this.#metrics.legacyEquivalentFileReads += legacyEquivalentFileReads;
    this.#metrics.avoidedFileReads = Math.max(0, this.#metrics.legacyEquivalentFileReads - this.#metrics.filesRead);
  }

  metrics(): MechanicalContextMetrics {
    this.#assertLive();
    return Object.freeze({ ...this.#metrics });
  }

  dispose(): void {
    this.#toolResults.clear();
    this.#asts = undefined;
    this.#parseCache = undefined;
    this.#importGraph = undefined;
    this.#disposed = true;
  }

  #assertLive(): void {
    if (this.#disposed) throw new Error("mechanical scan context used after its scan lifetime ended");
  }
}
