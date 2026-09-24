import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, join, normalize, relative, resolve } from "node:path";
import ts from "typescript";
import { DETERMINISTIC_DRY_RUN_FILES, validateDryRunFamily } from "./dry-run-artifacts.js";

const ENTRYPOINTS = ["src/cli/dry-run.ts"] as const;

export interface DryRunDependencyClosure {
  files: Set<string>;
  trees: Set<string>;
  unresolved: string[];
}

export interface RelevanceDecision {
  relevant: boolean;
  reason: "producer-dependency" | "producer-data" | "unknown" | "proved-unrelated-docs";
  matches: string[];
  dependencyCount: number;
  unresolved: string[];
}

function repoPath(repoRoot: string, absolute: string): string {
  return relative(repoRoot, absolute).split("\\").join("/");
}

function resolveLocalSpecifier(repoRoot: string, importer: string, specifier: string): string | undefined {
  if (!specifier.startsWith(".")) return undefined;
  const base = resolve(repoRoot, dirname(importer), specifier);
  const candidates = extname(base)
    ? [base, base.replace(/\.js$/, ".ts"), base.replace(/\.js$/, ".mjs")]
    : [base, `${base}.ts`, `${base}.mjs`, `${base}.js`, join(base, "index.ts"), join(base, "index.mjs")];
  return candidates.find((candidate) => existsSync(candidate));
}

function registerUrlInput(repoRoot: string, importer: string, specifier: string, closure: DryRunDependencyClosure): void {
  const absolute = resolve(repoRoot, dirname(importer), specifier);
  const path = repoPath(repoRoot, absolute).replace(/\/$/, "");
  if (specifier.endsWith("/") || (existsSync(absolute) && !extname(absolute))) closure.trees.add(path);
  else if (existsSync(absolute)) closure.files.add(path);
  else closure.unresolved.push(`${importer} -> ${specifier}`);
}

/** Derive the producer's local module graph and literal file/directory inputs from its real entrypoint. */
export function discoverDryRunDependencies(repoRoot: string): DryRunDependencyClosure {
  const closure: DryRunDependencyClosure = { files: new Set(), trees: new Set(), unresolved: [] };
  const pending: string[] = [...ENTRYPOINTS];
  while (pending.length > 0) {
    const file = pending.pop()!;
    if (closure.files.has(file)) continue;
    const absolute = resolve(repoRoot, file);
    if (!existsSync(absolute)) {
      closure.unresolved.push(file);
      continue;
    }
    closure.files.add(file);
    const source = readFileSync(absolute, "utf8");
    const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
    const imports: string[] = [];
    const urlInputs: string[] = [];
    const inspect = (node: ts.Node): void => {
      if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) imports.push(node.moduleSpecifier.text);
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword && node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0]!)) imports.push(node.arguments[0]!.text);
      if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "URL" && node.arguments?.length === 2 && ts.isStringLiteral(node.arguments[0]!)) {
        const second = node.arguments[1]!.getText(sourceFile).replaceAll(/\s/g, "");
        if (second === "import.meta.url" && node.arguments[0]!.text.startsWith(".")) urlInputs.push(node.arguments[0]!.text);
      }
      ts.forEachChild(node, inspect);
    };
    inspect(sourceFile);
    for (const specifier of imports) {
      if (!specifier.startsWith(".")) continue;
      const resolved = resolveLocalSpecifier(repoRoot, file, specifier);
      if (!resolved) closure.unresolved.push(`${file} -> ${specifier}`);
      else pending.push(repoPath(repoRoot, resolved));
    }
    for (const specifier of urlInputs) registerUrlInput(repoRoot, file, specifier, closure);
  }

  // These are runtime-selected inputs rather than imports: the calibration target copied into the
  // scan, retained dynamic evidence, the binary installer, and the generated family being checked.
  // Their roots come from the shipping dry-run invocation/workflow contract, while source modules
  // (including tools/pii-classify.mjs) are discovered recursively above.
  closure.trees.add("targets/calibration");
  closure.trees.add(".github/actions/mechanical-binaries");
  closure.files.add("dry-run/dynamic-scorecard.json");
  closure.files.add(".github/workflows/dry-run-drift.yml");
  closure.files.add("package.json");
  closure.files.add("pnpm-lock.yaml");
  for (const member of DETERMINISTIC_DRY_RUN_FILES) closure.files.add(`dry-run/${member}`);
  return closure;
}

function isProvedUnrelatedDocs(path: string): boolean {
  return path === "README.md" || path === "AGENTS.md" || path === "CLAUDE.md" || path === "MODULES.md" || path === "SESSION.md" || /^docs\/.*\.md$/i.test(path);
}

export function classifyDryRunChanges(repoRoot: string, changedPaths: readonly string[]): RelevanceDecision {
  const closure = discoverDryRunDependencies(repoRoot);
  const normalized = changedPaths.map((path) => normalize(path).split("\\").join("/").replace(/^\.\//, ""));
  const moduleMatches = normalized.filter((path) => closure.files.has(path));
  if (moduleMatches.length > 0) return { relevant: true, reason: "producer-dependency", matches: moduleMatches, dependencyCount: closure.files.size, unresolved: closure.unresolved };
  const dataMatches = normalized.filter((path) => [...closure.trees].some((tree) => path === tree || path.startsWith(`${tree}/`)));
  if (dataMatches.length > 0) return { relevant: true, reason: "producer-data", matches: dataMatches, dependencyCount: closure.files.size, unresolved: closure.unresolved };
  if (normalized.length > 0 && normalized.every(isProvedUnrelatedDocs) && closure.unresolved.length === 0) {
    return { relevant: false, reason: "proved-unrelated-docs", matches: normalized, dependencyCount: closure.files.size, unresolved: [] };
  }
  // An unclassified path or an unresolved edge is uncertainty, never evidence that output cannot
  // change. Regeneration is the safe result and makes new dependency shapes fail closed.
  return { relevant: true, reason: "unknown", matches: normalized, dependencyCount: closure.files.size, unresolved: closure.unresolved };
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value).filter(([, child]) => child !== undefined).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => `${JSON.stringify(key)}:${canonical(child)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "undefined";
}

export interface FamilyComparison {
  ok: boolean;
  members: readonly string[];
  differences: string[];
  timingExcluded: true;
}

/** Validate both families through the owning contract, then compare every owned deterministic member. */
export function compareDryRunFamilies(committedDir: string, freshDir: string): FamilyComparison {
  const differences: string[] = [];
  for (const [name, dir] of [["committed", committedDir], ["fresh", freshDir]] as const) {
    const validation = validateDryRunFamily(dir);
    if (!validation.ok) differences.push(`${name} family violates its semantic/provenance contract: ${validation.errors.join("; ")}`);
  }
  for (const member of DETERMINISTIC_DRY_RUN_FILES) {
    try {
      const committed = JSON.parse(readFileSync(join(committedDir, member), "utf8")) as unknown;
      const fresh = JSON.parse(readFileSync(join(freshDir, member), "utf8")) as unknown;
      if (canonical(committed) !== canonical(fresh)) differences.push(`${member} differs`);
    } catch (error) {
      differences.push(`${member} could not be compared: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return { ok: differences.length === 0, members: DETERMINISTIC_DRY_RUN_FILES, differences, timingExcluded: true };
}
