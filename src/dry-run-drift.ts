import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, extname, join, normalize, relative, resolve } from "node:path";
import ts from "typescript";
import { DETERMINISTIC_DRY_RUN_FILES, validateDryRunFamily } from "./dry-run-artifacts.js";
import { isDirectorySafe } from "./fs-walk.js";

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

function crossesLink(repoRoot: string, absolute: string): boolean {
  return realpathSync(absolute) !== resolve(realpathSync(repoRoot), repoPath(repoRoot, absolute));
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
  if (existsSync(absolute) && crossesLink(repoRoot, absolute)) closure.unresolved.push(`${importer} -> linked input: ${specifier}`);
  if (specifier.endsWith("/") || isDirectorySafe(absolute)) closure.trees.add(path);
  else if (existsSync(absolute)) closure.files.add(path);
  else closure.unresolved.push(`${importer} -> ${specifier}`);
}

const FILE_READS = new Set(["readFile", "readFileSync", "createReadStream", "open", "openSync", "opendir", "opendirSync", "readdir", "readdirSync", "glob", "globSync"]);
const PROCESS_CALLS = new Set(["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"]);
const SOURCE_EXTENSION = /\.(?:[cm]?[jt]s|tsx|jsx)$/;

function literal(node: ts.Node | undefined): string | undefined {
  return node && (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)) ? node.text : undefined;
}

/** Derive the producer's local module graph and literal file/directory inputs from its real entrypoint. */
export function discoverDryRunDependencies(repoRoot: string): DryRunDependencyClosure {
  const closure: DryRunDependencyClosure = { files: new Set(), trees: new Set(), unresolved: [] };
  const pending: string[] = [...ENTRYPOINTS];
  const visited = new Set<string>();
  while (pending.length > 0) {
    const file = pending.pop()!;
    if (visited.has(file)) continue;
    visited.add(file);
    const absolute = resolve(repoRoot, file);
    if (!existsSync(absolute)) {
      closure.unresolved.push(file);
      continue;
    }
    closure.files.add(file);
    if (crossesLink(repoRoot, absolute)) closure.unresolved.push(`${file}: linked source inputs are not statically closed`);
    const source = readFileSync(absolute, "utf8");
    const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
    const imports: string[] = [];
    const urlInputs: string[] = [];
    const inputBindings = new Map<string, string>();
    const inputNamespaces = new Set<string>();
    const unresolved = (node: ts.Node, reason: string): void => {
      const line = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
      closure.unresolved.push(`${file}:${line}: ${reason}`);
    };
    // Track imported aliases as well as namespace calls. An escaped input capability is not a
    // closed dependency graph: we deliberately regenerate rather than infer a runtime argument.
    for (const statement of sourceFile.statements) {
      if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
      const module = statement.moduleSpecifier.text;
      if (!/^(?:node:)?(?:fs(?:\/promises)?|child_process)$/.test(module)) continue;
      const bindings = statement.importClause?.namedBindings;
      if (statement.importClause?.name) inputNamespaces.add(statement.importClause.name.text);
      if (bindings && ts.isNamespaceImport(bindings)) inputNamespaces.add(bindings.name.text);
      if (bindings && ts.isNamedImports(bindings)) {
        for (const binding of bindings.elements) {
          const api = (binding.propertyName ?? binding.name).text;
          inputBindings.set(binding.name.text, api);
        }
      }
    }
    const localInput = (node: ts.Node, value: string, executable = false): void => {
      const absoluteInput = resolve(repoRoot, value);
      const path = repoPath(repoRoot, absoluteInput);
      if (path === ".." || path.startsWith("../")) {
        unresolved(node, `input outside repository: ${value}`);
      } else if (!existsSync(absoluteInput)) {
        unresolved(node, `missing input: ${value}`);
      } else {
        if (crossesLink(repoRoot, absoluteInput)) unresolved(node, `linked input: ${value}`);
        if (isDirectorySafe(absoluteInput)) closure.trees.add(path);
        else closure.files.add(path);
        if (executable && SOURCE_EXTENSION.test(path)) pending.push(path);
      }
    };
    const inspect = (node: ts.Node): void => {
      if (ts.isImportEqualsDeclaration(node)) unresolved(node, "import-equals runtime module inputs");
      if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) imports.push(node.moduleSpecifier.text);
      if (ts.isCallExpression(node)) {
        if (node.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(node.expression) && node.expression.text === "require")) {
          const specifier = literal(node.arguments[0]);
          if (specifier === undefined) unresolved(node, "computed module import");
          else {
            imports.push(specifier);
            if (specifier.startsWith("node:")) unresolved(node, "dynamically acquired builtin inputs");
          }
        }
        const callee = node.expression;
        let api: string | undefined;
        if (ts.isIdentifier(callee)) api = inputBindings.get(callee.text);
        else if (ts.isPropertyAccessExpression(callee)) {
          api = callee.name.text;
          if (ts.isIdentifier(callee.expression) && inputNamespaces.has(callee.expression.text) && !FILE_READS.has(api) && !PROCESS_CALLS.has(api)) {
            unresolved(node, `unmodeled input operation: ${api}`);
          }
        } else if (ts.isElementAccessExpression(callee) && ts.isIdentifier(callee.expression) && inputNamespaces.has(callee.expression.text)) {
          api = literal(callee.argumentExpression);
          if (api === undefined) unresolved(node, "computed input operation");
        }
        if (api && FILE_READS.has(api)) {
          const input = literal(node.arguments[0]);
          if (input === undefined) unresolved(node, `computed ${api} input`);
          else localInput(node, input);
        } else if (api && PROCESS_CALLS.has(api)) {
          // Even a known external executable can read cwd/config/environment-selected inputs.
          // Follow literal local scripts too, but never claim those describe the whole process.
          unresolved(node, `${api} runtime inputs are not statically closed`);
          const args = node.arguments[1];
          const candidates = [literal(node.arguments[0]), ...(args && ts.isArrayLiteralExpression(args) ? args.elements.map(literal) : [])];
          for (const candidate of candidates) {
            if (candidate && SOURCE_EXTENSION.test(candidate)) localInput(node, candidate, true);
          }
        } else if (api && ((ts.isIdentifier(callee) && inputBindings.has(callee.text))
          || (ts.isElementAccessExpression(callee) && ts.isIdentifier(callee.expression) && inputNamespaces.has(callee.expression.text)))) {
          unresolved(node, `unmodeled input operation: ${api}`);
        }
      }
      if (ts.isIdentifier(node) && inputBindings.has(node.text) && !ts.isImportSpecifier(node.parent)
        && !(ts.isCallExpression(node.parent) && node.parent.expression === node)) {
        unresolved(node, `input capability ${node.text} is passed indirectly`);
      }
      if (ts.isIdentifier(node) && inputNamespaces.has(node.text)
        && !ts.isNamespaceImport(node.parent) && !ts.isImportClause(node.parent)
        && !((ts.isPropertyAccessExpression(node.parent) || ts.isElementAccessExpression(node.parent)) && node.parent.expression === node)) {
        unresolved(node, `input namespace ${node.text} is passed indirectly`);
      }
      if ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node))
        && ts.isIdentifier(node.expression) && inputNamespaces.has(node.expression.text)
        && !(ts.isCallExpression(node.parent) && node.parent.expression === node)) {
        unresolved(node, `input operation on ${node.expression.text} is passed indirectly`);
      }
      if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "URL" && node.arguments?.length === 2) {
        const specifier = literal(node.arguments[0]);
        const second = node.arguments[1]!.getText(sourceFile).replaceAll(/\s/g, "");
        if (second === "import.meta.url") {
          if (specifier?.startsWith(".")) urlInputs.push(specifier);
          else if (specifier === undefined) unresolved(node, "computed import-relative URL input");
        }
      }
      ts.forEachChild(node, inspect);
    };
    inspect(sourceFile);
    for (const specifier of imports) {
      if (!specifier.startsWith(".")) {
        // Package code is pinned by the lockfile, but its runtime input choices are not described
        // by this local graph. Do not use a missing edge to certify an unrelated-docs no-op.
        if (!specifier.startsWith("node:")) closure.unresolved.push(`${file} -> external module inputs: ${specifier}`);
        continue;
      }
      const resolved = resolveLocalSpecifier(repoRoot, file, specifier);
      if (!resolved) closure.unresolved.push(`${file} -> ${specifier}`);
      else pending.push(repoPath(repoRoot, resolved));
    }
    for (const specifier of urlInputs) {
      registerUrlInput(repoRoot, file, specifier, closure);
      if (SOURCE_EXTENSION.test(specifier)) pending.push(repoPath(repoRoot, resolve(repoRoot, dirname(file), specifier)));
    }
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
  // Regenerate when an unclassified path or unresolved edge leaves the effect on output uncertain.
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
