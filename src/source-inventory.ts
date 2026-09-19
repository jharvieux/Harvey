// Product-source inventory shared by scanners that need to distinguish authored paths from
// dependency stores and configured build output. Directory names such as `reports`, `dist`, and
// `vendor` are not evidence by themselves: a product can legitimately author code below each.

import { existsSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, extname, join, normalize, relative, resolve, sep } from "node:path";
import ts from "typescript";
import { readEntriesSafe } from "./fs-walk.js";
import { discoverWorkspaceInventory } from "./workspaces.js";

export interface SourceExclusion {
  path: string;
  reason: string;
  match: "anchored" | "any-depth" | "exact";
}

export interface SourceInventoryGap {
  kind?: "source-alias";
  path: string;
  reason: string;
}

export interface ProductSourceInventory {
  excludedDirectories: readonly SourceExclusion[];
  unresolvedConfigurations: readonly SourceInventoryGap[];
  compilerInputs: readonly string[];
  exclusionsFor(path: string): readonly SourceExclusion[];
  excludedDirectoryFor(path: string): SourceExclusion | undefined;
  jscpdIgnoreGlobs: readonly string[];
}

const FIXED_BOUNDARIES: readonly SourceExclusion[] = [
  { path: ".git", match: "any-depth", reason: "Git metadata is repository history, not product source" },
  { path: "node_modules", match: "any-depth", reason: "installed package dependencies are not product source" },
];

const VITE_CONFIG_NAMES = ["vite.config.ts", "vite.config.js", "vite.config.mjs", "vite.config.cjs", "vite.config.mts", "vite.config.cts"];
const STRYKER_CONFIG_NAMES = [
  "stryker.config.json", "stryker.config.jsonc", "stryker.config.js", "stryker.config.ts",
  "stryker.config.mjs", "stryker.config.cjs", "stryker.config.mts", "stryker.config.cts",
];

const alwaysExcluded = Object.fromEntries(FIXED_BOUNDARIES.map((entry) => [entry.path, entry.reason]));

function posix(path: string): string {
  return normalize(path).split(sep).join("/").replace(/^\.\//, "").replace(/\/$/, "");
}

function readJsonc(path: string): { value?: Record<string, unknown>; error?: string } {
  try {
    const parsed = ts.parseConfigFileTextToJson(path, readFileSync(path, "utf8"));
    if (parsed.error) return { error: ts.flattenDiagnosticMessageText(parsed.error.messageText, " ") };
    return typeof parsed.config === "object" && parsed.config !== null
      ? { value: parsed.config as Record<string, unknown> }
      : { error: "configuration root is not an object" };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

function readJson(path: string): Record<string, unknown> | undefined {
  return readJsonc(path).value;
}

function unwrapExpression(node: ts.Expression): ts.Expression {
  let current = node;
  while (
    ts.isParenthesizedExpression(current)
    || ts.isAsExpression(current)
    || ts.isSatisfiesExpression(current)
    || ts.isTypeAssertionExpression(current)
  ) current = current.expression;
  if (
    ts.isCallExpression(current)
    && current.arguments.length === 1
    && ((ts.isIdentifier(current.expression) && current.expression.text === "defineConfig")
      || (ts.isPropertyAccessExpression(current.expression) && current.expression.name.text === "defineConfig"))
  ) return unwrapExpression(current.arguments[0]!);
  return current;
}

function staticValue(node: ts.Expression): unknown | undefined {
  const value = unwrapExpression(node);
  if (ts.isStringLiteralLike(value)) return value.text;
  if (ts.isNumericLiteral(value)) return Number(value.text);
  if (value.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (value.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (value.kind === ts.SyntaxKind.NullKeyword) return null;
  if (ts.isArrayLiteralExpression(value)) {
    const items: unknown[] = [];
    for (const element of value.elements) {
      if (ts.isSpreadElement(element)) return undefined;
      const item = staticValue(element as ts.Expression);
      if (item === undefined) return undefined;
      items.push(item);
    }
    return items;
  }
  if (!ts.isObjectLiteralExpression(value)) return undefined;
  const object: Record<string, unknown> = {};
  for (const property of value.properties) {
    if (!ts.isPropertyAssignment(property)) return undefined;
    const name = ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) || ts.isNumericLiteral(property.name)
      ? property.name.text
      : undefined;
    if (name === undefined) return undefined;
    const child = staticValue(property.initializer);
    if (child === undefined) return undefined;
    object[name] = child;
  }
  return object;
}

/** Read only a literal exported object. Imports, spreads, identifiers and computed values stay unresolved. */
function readConfigExportExpression(path: string): { expression?: ts.Expression; error?: string; executable?: boolean } {
  try {
    const source = ts.createSourceFile(path, readFileSync(path, "utf8"), ts.ScriptTarget.Latest, true,
      path.endsWith(".ts") || path.endsWith(".mts") || path.endsWith(".cts") ? ts.ScriptKind.TS : ts.ScriptKind.JS);
    let expression: ts.Expression | undefined;
    let executable = false;
    for (const statement of source.statements) {
      if (ts.isExportAssignment(statement) && !statement.isExportEquals) {
        expression = statement.expression;
        continue;
      }
      if (
        ts.isExpressionStatement(statement)
        && ts.isBinaryExpression(statement.expression)
        && statement.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken
        && statement.expression.left.getText(source) === "module.exports"
      ) {
        expression = statement.expression.right;
        continue;
      }
      // Even an import used only to wrap the object can execute module initialization. Consumers
      // that replace a JS/TS config must preserve that behavior through a wrapper rather than
      // serializing the literal object and silently dropping the import.
      if (!(ts.isImportDeclaration(statement) && statement.importClause?.isTypeOnly)) executable = true;
    }
    return expression ? { expression, executable } : { error: "no static default/module.exports object" };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

export function readStaticConfigObject(path: string): { value?: Record<string, unknown>; error?: string; executable?: boolean } {
  if ([".json", ".jsonc"].includes(extname(path))) return { ...readJsonc(path), executable: false };
  const parsed = readConfigExportExpression(path);
  if (!parsed.expression) return parsed;
  try {
    const value = staticValue(parsed.expression);
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? { value: value as Record<string, unknown>, executable: parsed.executable }
      : { error: "export is not a fully static object" };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

function objectProperty(expression: ts.Expression, name: string): { expression?: ts.Expression; unresolved?: boolean } {
  const object = unwrapExpression(expression);
  if (!ts.isObjectLiteralExpression(object)) return { unresolved: true };
  let found: ts.Expression | undefined;
  let unresolved = false;
  for (const property of object.properties) {
    if (ts.isSpreadAssignment(property)) {
      unresolved = true;
      continue;
    }
    const propertyName = "name" in property && property.name
      && (ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) || ts.isNumericLiteral(property.name))
      ? property.name.text
      : undefined;
    if (propertyName === undefined) {
      unresolved = true;
      continue;
    }
    if (propertyName !== name) continue;
    if (ts.isPropertyAssignment(property)) found = property.initializer;
    else unresolved = true;
  }
  return { ...(found ? { expression: found } : {}), ...(unresolved ? { unresolved: true } : {}) };
}

// Vite's output remains `dist` when unrelated config fields are dynamic. Reading the whole object
// would conflate an executable lib-entry/plugin expression with an unknown output boundary and
// make quality-scan reject findings that Knip produced successfully.
function readViteOutputDirectory(path: string): { output?: string; error?: string } {
  const parsed = readConfigExportExpression(path);
  if (!parsed.expression) return { error: parsed.error };
  const build = objectProperty(parsed.expression, "build");
  if (build.unresolved) return { error: "Vite build output is obscured by a spread or computed property" };
  if (!build.expression) return { output: "dist" };
  const outDir = objectProperty(build.expression, "outDir");
  if (outDir.unresolved) return { error: "Vite build.outDir is obscured by a spread or computed property" };
  if (!outDir.expression) return { output: "dist" };
  const value = staticValue(outDir.expression);
  return typeof value === "string"
    ? { output: value }
    : { error: "Vite build.outDir is not a static string" };
}

function hasDependency(pkg: Record<string, unknown> | undefined, name: string): boolean {
  if (!pkg) return false;
  return ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"].some((key) => {
    const entries = pkg[key];
    return typeof entries === "object" && entries !== null && name in entries;
  });
}

function addRelativeDirectory(exclusions: Record<string, string>, value: unknown, reason: string): void {
  if (typeof value !== "string" || value.length === 0) return;
  const normalized = normalize(value).split(sep).join("/").replace(/^\.\//, "").replace(/\/$/, "");
  if (!normalized || normalized === "." || normalized.startsWith("../") || normalized.startsWith("/")) return;
  exclusions[normalized] = reason;
}

function resolveTsOutput(configPath: string, seen = new Set<string>()): { output?: string; declaredAt?: string } {
  const absolute = resolve(configPath);
  if (seen.has(absolute)) return {};
  seen.add(absolute);
  const config = readJson(absolute);
  const compiler = config?.compilerOptions;
  const output = typeof compiler === "object" && compiler !== null ? (compiler as Record<string, unknown>).outDir : undefined;
  if (typeof output === "string") return { output, declaredAt: absolute };
  const inherited = config?.extends;
  if (typeof inherited !== "string" || (!inherited.startsWith(".") && !inherited.startsWith("/"))) return {};
  let parent = resolve(dirname(absolute), inherited);
  if (!extname(parent)) parent += ".json";
  return existsSync(parent) ? resolveTsOutput(parent, seen) : {};
}

interface TypeScriptOutputPlan {
  configPath: string;
  outputDirectories: readonly string[];
  outputDeclaredAt?: string;
  inputFiles: readonly string[];
  emittedFiles: readonly string[];
  referencedConfigs: readonly string[];
  emissionDisabled?: string;
  error?: string;
}

function pathIsInside(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !rel.startsWith("/"));
}

function typescriptOutputPlan(configPath: string): TypeScriptOutputPlan {
  const diagnostics: ts.Diagnostic[] = [];
  const parsed = ts.getParsedCommandLineOfConfigFile(configPath, {}, {
    ...ts.sys,
    onUnRecoverableConfigFileDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
  });
  if (!parsed) {
    return {
      configPath,
      outputDirectories: [],
      inputFiles: [],
      emittedFiles: [],
      referencedConfigs: [],
      error: diagnostics.length > 0
        ? diagnostics.map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, " ")).join("; ")
        : "TypeScript could not resolve the effective configuration",
    };
  }
  // TS18002/TS18003 describe an empty project population, not an unreadable output boundary.
  // They are common in solution configs and must not turn an otherwise exact inventory partial.
  const errors = [...diagnostics, ...parsed.errors.filter((diagnostic) => ![18002, 18003].includes(diagnostic.code))];
  const declared = resolveTsOutput(configPath);
  const emittedFiles: string[] = [];
  // Config fileNames are entry points, not the compiler's complete input population. Resolve
  // imports, triple-slash references and project references before classifying any output path.
  const program = ts.createProgram({ rootNames: parsed.fileNames, options: parsed.options, projectReferences: parsed.projectReferences });
  const inputFiles = program.getSourceFiles()
    .filter((file) => !program.isSourceFileDefaultLibrary(file))
    .map((file) => resolve(file.fileName));
  errors.push(...program.getOptionsDiagnostics());
  // The callback records compiler-supported emission without writing into the audited tree.
  // Filename prediction ignores noEmit/noEmitOnError and can even identify authored JS as output.
  const emission = program.emit(undefined, (file) => emittedFiles.push(resolve(file)));
  errors.push(...emission.diagnostics);
  const outputDirectories = [parsed.options.outDir, parsed.options.declarationDir]
    .filter((path): path is string => typeof path === "string").map((path) => resolve(path));
  return {
    configPath,
    outputDirectories: [...new Set(outputDirectories)],
    ...(declared.declaredAt ? { outputDeclaredAt: declared.declaredAt } : {}),
    inputFiles,
    emittedFiles: [...new Set(emittedFiles)],
    referencedConfigs: (parsed.projectReferences ?? []).map(ts.resolveProjectReferencePath),
    ...(parsed.options.noEmit ? { emissionDisabled: "noEmit is enabled" }
      : emission.emitSkipped && emittedFiles.length === 0 ? { emissionDisabled: "the compiler blocked emission" } : {}),
    ...(errors.length > 0 ? {
      error: errors.map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, " ")).join("; "),
    } : {}),
  };
}

function npmrcStoreDir(path: string): string | undefined {
  try {
    for (const raw of readFileSync(path, "utf8").split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) continue;
      const match = /^(?:store-dir|storeDir)\s*=\s*(.+)$/.exec(line);
      if (!match) continue;
      const value = match[1]!.trim().replace(/^['"]|['"]$/g, "");
      return /\$\{|%[^%]+%/.test(value) ? undefined : value;
    }
  } catch { /* unreadable configuration remains unresolved */ }
  return undefined;
}

interface ConfiguredSourceBoundaries {
  sourceFiles: string[];
  directories: Record<string, string>;
  files: Record<string, string>;
  gaps: SourceInventoryGap[];
  compilerInputs: readonly string[];
}

interface StaticCopyStep {
  source: string;
  destination: string;
  order: number;
}

function staticShellPath(token: string, variables: ReadonlyMap<string, string>): string | undefined {
  let value = token.trim();
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1);
  }
  value = value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (_match, braced: string | undefined, plain: string | undefined) => {
    return variables.get(braced ?? plain ?? "") ?? "\0";
  });
  if (value.includes("\0") || /[$`*?{}[\]]/.test(value)) return undefined;
  return resolve(value);
}

// Read only the narrow shell shape needed to prove that a committed tree is an install-time
// overlay: static `cp source destination` commands plus literal path variables. The script is never
// executed. An arbitrary directory name (including `patches`) is not evidence on its own.
function staticCopySteps(scriptPath: string): StaticCopyStep[] {
  const lines = readFileSync(scriptPath, "utf8").split(/\r?\n/);
  const variables = new Map<string, string>();
  const scriptDir = dirname(scriptPath);
  for (let pass = 0; pass < lines.length; pass += 1) {
    let changed = false;
    for (const line of lines) {
      const assignment = /^\s*([A-Za-z_][A-Za-z0-9_]*)=(.+?)\s*$/.exec(line);
      if (!assignment || variables.has(assignment[1]!)) continue;
      const [, name, rawValue] = assignment;
      if (/dirname\s+["']?\$\{?BASH_SOURCE\[0\]\}?/.test(rawValue!)) {
        variables.set(name!, scriptDir);
        changed = true;
        continue;
      }
      let expression = rawValue!.trim();
      if (expression.startsWith('"') && expression.endsWith('"')) expression = expression.slice(1, -1);
      const physicalDir = /^\$\(cd\s+["']?(.+?)["']?\s+&&\s+pwd\)$/.exec(expression);
      const resolved = staticShellPath(physicalDir?.[1] ?? expression, variables);
      if (resolved) {
        variables.set(name!, resolved);
        changed = true;
      }
    }
    if (!changed) break;
  }

  const steps: StaticCopyStep[] = [];
  for (const [order, line] of lines.entries()) {
    const command = /^\s*cp((?:\s+-[^\s]+)*)\s+(\S+)\s+(\S+)\s*$/.exec(line);
    if (!command) continue;
    const flags = command[1]!.trim().split(/\s+/).filter(Boolean);
    // Interactive, no-clobber, update-only, dereference and other unmodelled modes do not prove
    // that the destination is overwritten. Preserve source unless every supplied short flag has
    // simple file-copy semantics that this narrow parser understands.
    if (flags.some((flag) => !/^-[afprRvT]+$/.test(flag))) continue;
    const source = staticShellPath(command[2]!, variables);
    const destination = staticShellPath(command[3]!, variables);
    if (source && destination) steps.push({ source, destination, order });
  }
  return steps;
}

function relativeInside(root: string, path: string): string | undefined {
  const rel = posix(relative(root, path));
  return rel === ".." || rel.startsWith("../") || resolve(root, ...rel.split("/")) !== resolve(path) ? undefined : rel;
}

function filesBelow(sourceFiles: readonly string[], relativeDirectory: string): string[] {
  return sourceFiles.filter((path) => path.startsWith(`${relativeDirectory}/`));
}

function canonicalExistingPath(path: string): string | undefined {
  try {
    return realpathSync(path);
  } catch {
    return undefined;
  }
}

function canonicalPathIsInside(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !rel.startsWith("/"));
}

function configuredInactiveOverlays(root: string, sourceFiles: readonly string[]): Record<string, string> {
  const scripts = sourceFiles.filter((path) => path.endsWith(".sh")).map((path) => join(root, path));

  const exclusions: Record<string, string> = {};
  for (const scriptPath of scripts) {
    const steps = staticCopySteps(scriptPath);
    const overlayDestinations = new Map<string, Set<string>>();
    for (const step of steps) {
      const source = relativeInside(root, step.source);
      const destination = relativeInside(root, step.destination);
      if (!source || !destination || !existsSync(step.source) || !existsSync(step.destination)) continue;
      const sourceIdentity = canonicalExistingPath(step.source);
      const destinationIdentity = canonicalExistingPath(step.destination);
      if (!sourceIdentity || !destinationIdentity || sourceIdentity === destinationIdentity) continue;
      const backedUpFirst = steps.some((prior) => {
        if (prior.order >= step.order) return false;
        return canonicalExistingPath(prior.source) === destinationIdentity;
      });
      if (!backedUpFirst) continue;
      const destinations = overlayDestinations.get(source) ?? new Set<string>();
      destinations.add(destinationIdentity);
      overlayDestinations.set(source, destinations);
    }
    if (overlayDestinations.size < 2) continue;

    const candidateDirectories = new Set<string>();
    for (const source of overlayDestinations.keys()) {
      let candidate = posix(dirname(source));
      let accepted: string | undefined;
      while (candidate !== "." && candidate !== "") {
        const population = filesBelow(sourceFiles, candidate);
        if (population.length < 2 || population.some((file) => !overlayDestinations.has(file))) break;
        const candidateIdentity = canonicalExistingPath(join(root, candidate));
        if (!candidateIdentity || population.some((file) => {
          return [...(overlayDestinations.get(file) ?? [])].some((destination) => canonicalPathIsInside(candidateIdentity, destination));
        })) break;
        accepted = candidate;
        candidate = posix(dirname(candidate));
      }
      if (accepted) candidateDirectories.add(accepted);
    }
    const maximal = [...candidateDirectories].filter((candidate) => {
      return ![...candidateDirectories].some((other) => candidate !== other && candidate.startsWith(`${other}/`));
    });
    const script = posix(relative(root, scriptPath));
    for (const directory of maximal) {
      const count = filesBelow(sourceFiles, directory).length;
      exclusions[directory] = `${count} staged overlay files are copied over backed-up live product files by ${script}`;
    }
  }
  return exclusions;
}

function configuredOutputDirectories(root: string, pkg: Record<string, unknown> | undefined, inheritedInputs: readonly string[]): ConfiguredSourceBoundaries {
  const exclusions: Record<string, string> = {};
  const exactFiles: Record<string, string> = {};
  const gaps: SourceInventoryGap[] = [];
  const pnpm = existsSync(join(root, "pnpm-lock.yaml")) || existsSync(join(root, "pnpm-workspace.yaml"))
    || (typeof pkg?.packageManager === "string" && pkg.packageManager.startsWith("pnpm@"));
  if (pnpm) {
    exclusions[".pnpm-store"] = "pnpm package store declared by workspace/package-manager metadata";
    exclusions[".pnpm"] = "pnpm package store declared by workspace/package-manager metadata";
  }

  if (existsSync(join(root, "composer.json"))) exclusions.vendor = "Composer dependency directory declared by composer.json";
  if (existsSync(join(root, "go.mod"))) exclusions.vendor = "Go dependency vendor directory declared by go.mod";

  const scripts = pkg?.scripts;
  const scriptText = typeof scripts === "object" && scripts !== null ? Object.values(scripts).filter((v): v is string => typeof v === "string").join("\n") : "";
  if (/\b(?:vitest|jest|c8|nyc)\b[^\n]*\s--coverage\b/.test(scriptText)) {
    exclusions.coverage = "test coverage output declared by package scripts";
  }

  const viteConfig = VITE_CONFIG_NAMES
    .map((name) => join(root, name))
    .find(existsSync);
  if (viteConfig || hasDependency(pkg, "vite")) {
    let output: string | undefined = "dist";
    if (viteConfig) {
      output = readViteOutputDirectory(viteConfig).output;
    }
    addRelativeDirectory(exclusions, output, "Vite build output declared by Vite configuration");
  }

  const tsconfigs: string[] = [];
  const packages: string[] = [join(root, "package.json")];
  const composerConfigs: string[] = [];
  const goModules: string[] = [];
  const npmrcConfigs: string[] = [];
  const candidateFiles: string[] = [];
  const sourceAliases: Array<{ path: string; directory: boolean; reason: string }> = [];
  const internalAliases: Array<{ path: string; target: string; directory: boolean }> = [];
  const canonicalRoot = canonicalExistingPath(root) ?? resolve(root);
  const collectConfigs = (dir: string, ancestors: ReadonlySet<string>): void => {
    for (const entry of readEntriesSafe(dir).entries) {
      const rel = posix(relative(root, entry.path));
      const dependencyBoundary = exclusions[rel];
      if (Object.hasOwn(alwaysExcluded, entry.name)
        || /dependency (?:vendor )?directory|package store|pnpm store-dir declared/.test(dependencyBoundary ?? "")
        || (pnpm && [".pnpm-store", ".pnpm"].includes(entry.name))) continue;
      const identity = canonicalExistingPath(entry.path);
      const outside = identity !== undefined && !canonicalPathIsInside(canonicalRoot, identity);
      const cycle = entry.isDirectory && identity !== undefined && ancestors.has(identity);
      if (outside || cycle) {
        sourceAliases.push({ path: rel, directory: entry.isDirectory, reason: outside
          ? `Source alias ${rel} resolves outside the selected source tree; its external population is not assessed`
          : `Source directory alias ${rel} forms a cycle; its recursive population is not assessed` });
        continue;
      }
      if (identity && lstatSync(entry.path).isSymbolicLink()) internalAliases.push({
        path: rel, target: posix(relative(canonicalRoot, identity)), directory: entry.isDirectory,
      });
      if (!entry.isDirectory) candidateFiles.push(entry.path);
      if (entry.isDirectory) {
        collectConfigs(entry.path, new Set([...ancestors, identity ?? entry.path]));
      } else if (/^tsconfig(?:\.[\w.-]+)?\.json$/.test(entry.name)) {
        tsconfigs.push(entry.path);
      } else if (entry.name === "package.json" && entry.path !== join(root, "package.json")) {
        packages.push(entry.path);
      } else if (entry.name === "composer.json") {
        composerConfigs.push(entry.path);
      } else if (entry.name === "go.mod") {
        goModules.push(entry.path);
      } else if (entry.name === ".npmrc") {
        npmrcConfigs.push(entry.path);
      }
    }
  };
  collectConfigs(root, new Set([canonicalRoot]));
  const tsPlans: TypeScriptOutputPlan[] = [];
  const seenConfigs = new Set<string>();
  for (let index = 0; index < tsconfigs.length; index++) {
    const configPath = resolve(tsconfigs[index]!);
    if (seenConfigs.has(configPath)) continue;
    seenConfigs.add(configPath);
    const plan = typescriptOutputPlan(configPath);
    tsPlans.push(plan);
    tsconfigs.push(...plan.referencedConfigs);
  }
  const compilerInputs = [...new Set([...inheritedInputs, ...tsPlans.flatMap((plan) => plan.inputFiles)])];
  const inputIdentities = compilerInputs.map((path) => ({ path, canonical: canonicalExistingPath(path) }));
  const compilerInputPaths = new Set(inputIdentities.flatMap(({ path, canonical }) => canonical ? [path, canonical] : [path]));
  const isCompilerInput = (path: string): boolean => compilerInputPaths.has(path)
    || compilerInputPaths.has(canonicalExistingPath(path) ?? path);
  const inputsWithin = (directory: string): string[] => {
    const canonicalDirectory = canonicalExistingPath(directory);
    return inputIdentities.filter((input) => pathIsInside(directory, input.path)
      || (canonicalDirectory !== undefined && input.canonical !== undefined && pathIsInside(canonicalDirectory, input.canonical)))
      .map((input) => input.path);
  };
  for (const plan of tsPlans) {
    const configLabel = posix(relative(root, plan.configPath));
    if (plan.error) gaps.push({ path: configLabel, reason: `TypeScript effective configuration is incomplete: ${plan.error}` });
    const declaredAt = plan.outputDeclaredAt ? posix(relative(root, plan.outputDeclaredAt)) : configLabel;
    const reason = `TypeScript compiler output declared by ${declaredAt}`;
    for (const emitted of plan.emittedFiles) {
      if (!pathIsInside(root, emitted) || isCompilerInput(emitted)) continue;
      const emittedPath = posix(relative(root, emitted));
      if (emittedPath && emittedPath !== ".") exactFiles[emittedPath] = `${reason}; exact emitted artifact derived from the effective compiler inputs`;
    }
    for (const outputDirectory of plan.outputDirectories) {
      if (!pathIsInside(root, outputDirectory)) continue;
      const outputPath = posix(relative(root, outputDirectory));
      const overlappingInputs = inputsWithin(outputDirectory);
      if (!plan.emissionDisabled && !plan.error && overlappingInputs.length === 0) {
        addRelativeDirectory(exclusions, outputPath, reason);
        continue;
      }
      // Preserve inputs selected by another config and limit exclusions to observed emitted files.
      // Disabled emission leaves output-shaped filenames without generated-artifact provenance.
      gaps.push({
        path: configLabel,
        reason: overlappingInputs.length > 0
          ? `TypeScript output ${outputPath} overlaps ${overlappingInputs.length} effective compiler input file(s); ${plan.emissionDisabled ? `${plan.emissionDisabled}, so no emitted artifacts are excluded` : "exact emitted artifacts that are not compiler inputs are excluded"} and other paths are retained as candidate source`
          : `TypeScript output ${outputPath} cannot establish an exclusion because ${plan.emissionDisabled ?? "the effective configuration is incomplete"}; candidate source is retained`,
      });
    }
  }

  for (const configPath of composerConfigs) {
    const base = relative(root, dirname(configPath));
    addRelativeDirectory(exclusions, join(base, "vendor"), `Composer dependency directory declared by ${relative(root, configPath).split(sep).join("/")}`);
  }
  for (const configPath of goModules) {
    const base = relative(root, dirname(configPath));
    addRelativeDirectory(exclusions, join(base, "vendor"), `Go dependency vendor directory declared by ${relative(root, configPath).split(sep).join("/")}`);
  }
  for (const configPath of npmrcConfigs) {
    const configuredStore = npmrcStoreDir(configPath);
    if (configuredStore) addRelativeDirectory(exclusions, join(relative(root, dirname(configPath)), configuredStore), `pnpm store-dir declared by ${relative(root, configPath).split(sep).join("/")}`);
  }

  // Workspace packages can own their own Vite build directory or coverage command. Apply the
  // same evidence rules at each manifest rather than treating a root-level package.json as the
  // entire product configuration.
  for (const packagePath of packages) {
    const workspacePkg = readJson(packagePath);
    if (!workspacePkg) continue;
    const packageDir = dirname(packagePath);
    const base = relative(root, packageDir);
    const prefix = base === "" ? "" : `${base}/`;
    const workspacePnpm = pnpm || existsSync(join(packageDir, "pnpm-lock.yaml")) || existsSync(join(packageDir, "pnpm-workspace.yaml"))
      || (typeof workspacePkg.packageManager === "string" && workspacePkg.packageManager.startsWith("pnpm@"));
    if (workspacePnpm) {
      addRelativeDirectory(exclusions, `${prefix}.pnpm-store`, `pnpm package store declared by ${base === "" ? "package.json" : `${base}/package.json`}`);
      addRelativeDirectory(exclusions, `${prefix}.pnpm`, `pnpm package store declared by ${base === "" ? "package.json" : `${base}/package.json`}`);
    }
    const npmrc = join(packageDir, ".npmrc");
    const configuredStore = existsSync(npmrc) ? npmrcStoreDir(npmrc) : undefined;
    if (configuredStore) addRelativeDirectory(exclusions, join(base, configuredStore), `pnpm store-dir declared by ${base === "" ? ".npmrc" : `${base}/.npmrc`}`);
    if (existsSync(join(packageDir, "composer.json"))) addRelativeDirectory(exclusions, `${prefix}vendor`, `Composer dependency directory declared by ${base === "" ? "composer.json" : `${base}/composer.json`}`);
    if (existsSync(join(packageDir, "go.mod"))) addRelativeDirectory(exclusions, `${prefix}vendor`, `Go dependency vendor directory declared by ${base === "" ? "go.mod" : `${base}/go.mod`}`);
    const workspaceScripts = workspacePkg.scripts;
    const workspaceScriptText = typeof workspaceScripts === "object" && workspaceScripts !== null
      ? Object.values(workspaceScripts).filter((v): v is string => typeof v === "string").join("\n")
      : "";
    if (/\b(?:vitest|jest|c8|nyc)\b[^\n]*\s--coverage\b/.test(workspaceScriptText)) {
      addRelativeDirectory(exclusions, `${prefix}coverage`, `test coverage output declared by ${base === "" ? "package.json" : `${base}/package.json`}`);
    }
    const workspaceViteConfig = VITE_CONFIG_NAMES
      .map((name) => join(packageDir, name))
      .find(existsSync);
    if (workspaceViteConfig || hasDependency(workspacePkg, "vite")) {
      let output: string | undefined = "dist";
      if (workspaceViteConfig) {
        output = readViteOutputDirectory(workspaceViteConfig).output;
      }
      if (output) {
        const source = workspaceViteConfig
          ? relative(root, workspaceViteConfig).split(sep).join("/")
          : base === "" ? "package.json" : `${base}/package.json`;
        addRelativeDirectory(exclusions, join(base, output), `Vite build output declared by ${source}`);
      }
    }
  }

  const stryker = readJson(join(root, "stryker.config.json"));
  if (stryker) {
    addRelativeDirectory(exclusions, stryker.tempDirName, "Stryker temporary directory declared by stryker.config.json");
    const reporter = stryker.jsonReporter;
    if (typeof reporter === "object" && reporter !== null) {
      const fileName = (reporter as Record<string, unknown>).fileName;
      if (typeof fileName === "string") addRelativeDirectory(exclusions, dirname(fileName), "Stryker JSON report directory declared by stryker.config.json");
    }
  }
  for (const packagePath of packages) {
    const packageDir = dirname(packagePath);
    const configPath = STRYKER_CONFIG_NAMES.map((name) => join(packageDir, name)).find(existsSync);
    if (!configPath || configPath === join(root, "stryker.config.json")) continue;
    const config = readStaticConfigObject(configPath).value;
    if (!config) continue;
    const base = relative(root, packageDir);
    const label = relative(root, configPath).split(sep).join("/");
    if (typeof config.tempDirName === "string") {
      addRelativeDirectory(exclusions, join(base, config.tempDirName), `Stryker temporary directory declared by ${label}`);
    }
    const reporter = config.jsonReporter;
    if (typeof reporter === "object" && reporter !== null && typeof (reporter as Record<string, unknown>).fileName === "string") {
      addRelativeDirectory(exclusions, join(base, dirname((reporter as Record<string, unknown>).fileName as string)), `Stryker JSON report directory declared by ${label}`);
    }
  }
  // Prefer observed compiler inputs over a configured output directory's inferred role.
  // Retaining mixed directories keeps those source files available to the scanner population.
  for (const [path, reason] of Object.entries(exclusions)) {
    if (!/(?:output|coverage|temporary|report directory) declared/i.test(reason)) continue;
    if (reason.startsWith("TypeScript compiler output")) continue;
    const absolute = resolve(root, ...path.split("/"));
    const overlappingInputs = inputsWithin(absolute);
    if (overlappingInputs.length === 0) continue;
    delete exclusions[path];
    const alreadyDisclosed = gaps.some((gap) => gap.reason.includes(`output ${path} overlaps`));
    if (!alreadyDisclosed) gaps.push({
      path,
      reason: `Configured output ${path} overlaps ${overlappingInputs.length} effective TypeScript compiler input file(s); the ambiguous directory is retained as candidate source`,
    });
  }
  let aliasesByIdentity: Map<string, string[]> | undefined;
  const sourceFiles = candidateFiles.map((path) => posix(relative(root, path)));
  for (const [path, reason] of Object.entries(configuredInactiveOverlays(root, sourceFiles))) {
    const population = filesBelow(sourceFiles, path);
    const liveFiles = population.filter((file) => isCompilerInput(resolve(root, file)));
    if (liveFiles.length === 0) {
      exclusions[path] = reason;
      continue;
    }
    // Imported overlay files serve the current program as well as the installer. Keep their
    // ancestors traversable and narrow the inactive population to individually evidenced files.
    const inactiveFiles = population.filter((file) => !liveFiles.includes(file));
    if (inactiveFiles.length > 0 && !aliasesByIdentity) {
      aliasesByIdentity = new Map<string, string[]>();
      for (const file of candidateFiles) {
        const identity = canonicalExistingPath(file) ?? file;
        const aliases = aliasesByIdentity.get(identity) ?? [];
        aliases.push(posix(relative(root, file)));
        aliasesByIdentity.set(identity, aliases);
      }
    }
    for (const file of inactiveFiles) {
      const identity = canonicalExistingPath(resolve(root, file)) ?? resolve(root, file);
      for (const alias of aliasesByIdentity?.get(identity) ?? [file]) exactFiles[alias] = reason;
    }
    gaps.push({
      path,
      reason: `Staged install overlay ${path} overlaps ${liveFiles.length} effective TypeScript compiler input file(s); those live inputs are retained and ${inactiveFiles.length} inactive staged file(s) are excluded individually. Installer evidence: ${reason}`,
    });
  }
  for (const alias of sourceAliases) {
    const dependency = Object.entries(exclusions).some(([path, reason]) => /dependency (?:vendor )?directory|package store|pnpm store-dir declared/.test(reason)
      && matchesExclusion({ path, reason, match: "anchored" }, alias.path));
    if (dependency) continue;
    if (alias.directory) exclusions[alias.path] = alias.reason;
    else exactFiles[alias.path] = alias.reason;
    gaps.push({ kind: "source-alias", path: alias.path, reason: alias.reason });
  }
  const canonicalExclusions: SourceExclusion[] = [
    ...FIXED_BOUNDARIES,
    ...Object.entries(exclusions).map(([path, reason]): SourceExclusion => ({ path, reason, match: "anchored" })),
    ...Object.entries(exactFiles).map(([path, reason]): SourceExclusion => ({ path, reason, match: "exact" })),
  ];
  for (const alias of internalAliases) {
    for (const exclusion of canonicalExclusions) {
      if (matchesExclusion(exclusion, alias.target)) {
        if (alias.directory) exclusions[alias.path] = exclusion.reason;
        else exactFiles[alias.path] = exclusion.reason;
      } else if (alias.directory && exclusion.path.startsWith(`${alias.target}/`)) {
        const path = `${alias.path}/${exclusion.path.slice(alias.target.length + 1)}`;
        if (exclusion.match === "exact") exactFiles[path] = exclusion.reason;
        else exclusions[path] = exclusion.reason;
      }
    }
  }
  return { directories: exclusions, files: exactFiles, gaps, compilerInputs, sourceFiles };
}

function configurationGaps(root: string, sourceFiles: readonly string[], configuredGaps: readonly SourceInventoryGap[]): SourceInventoryGap[] {
  const gaps: SourceInventoryGap[] = [];
  for (const rel of sourceFiles) {
    const entry = { path: join(root, rel), name: basename(rel) };
    if (VITE_CONFIG_NAMES.includes(entry.name) || STRYKER_CONFIG_NAMES.includes(entry.name)) {
      if (VITE_CONFIG_NAMES.includes(entry.name)) {
        const parsed = readViteOutputDirectory(entry.path);
        if (!parsed.output) gaps.push({ path: rel, reason: `configuration output paths are unresolved: ${parsed.error}` });
      } else {
        const parsed = readStaticConfigObject(entry.path);
        if (!parsed.value) gaps.push({ path: rel, reason: `configuration output paths are unresolved: ${parsed.error}` });
      }
    } else if (/^tsconfig(?:\.[\w.-]+)?\.json$/.test(entry.name)) {
      const parsed = readJsonc(entry.path);
      if (!parsed.value) gaps.push({ path: rel, reason: `TypeScript configuration is not statically readable: ${parsed.error}` });
    } else if (entry.name === ".npmrc") {
      const text = readFileSync(entry.path, "utf8");
      const storeLine = text.split(/\r?\n/).map((line) => line.trim()).find((line) => /^(?:store-dir|storeDir)\s*=/.test(line));
      if (storeLine && /\$\{|%[^%]+%/.test(storeLine)) gaps.push({ path: rel, reason: "pnpm store-dir contains a dynamic environment reference" });
    }
  }
  return [...new Map([...gaps, ...configuredGaps].map((gap) => [`${gap.path}\0${gap.reason}`, gap])).values()]
    .sort((a, b) => a.path.localeCompare(b.path) || a.reason.localeCompare(b.reason));
}

function matchesExclusion(exclusion: SourceExclusion, path: string): boolean {
  const normalized = posix(path);
  if (exclusion.match === "anchored") {
    if (exclusion.path === ".") return true;
    return normalized === exclusion.path || normalized.startsWith(`${exclusion.path}/`);
  }
  if (exclusion.match === "exact") return normalized === exclusion.path;
  return normalized.split("/").includes(exclusion.path);
}

export function sourceExclusionGlob(exclusion: SourceExclusion): string {
  if (exclusion.match === "exact") return exclusion.path;
  if (exclusion.path === ".") return "**/*";
  return exclusion.match === "any-depth" ? `**/${exclusion.path}/**` : `${exclusion.path}/**`;
}

function inventoryFrom(
  entries: readonly SourceExclusion[],
  unresolvedConfigurations: readonly SourceInventoryGap[],
  compilerInputs: readonly string[],
): ProductSourceInventory {
  const exclusionsFor = (path: string): readonly SourceExclusion[] => entries.filter((entry) => matchesExclusion(entry, path));
  return {
    excludedDirectories: entries,
    unresolvedConfigurations,
    compilerInputs,
    exclusionsFor,
    excludedDirectoryFor: (path: string) => exclusionsFor(path)[0],
    jscpdIgnoreGlobs: entries.map(sourceExclusionGlob),
  };
}

/** Build the explicit product boundary from package and tool configuration. */
export function productSourceInventory(root: string, inheritedInputs: readonly string[] = []): ProductSourceInventory {
  const pkg = readJson(join(root, "package.json"));
  const configured = configuredOutputDirectories(root, pkg, inheritedInputs);
  const entries: SourceExclusion[] = [
    ...FIXED_BOUNDARIES,
    ...Object.entries(configured.directories).map(([path, reason]): SourceExclusion => ({
      path,
      reason,
      match: path === ".pnpm-store" || path === ".pnpm" ? "any-depth" : "anchored",
    })),
    ...Object.entries(configured.files).map(([path, reason]): SourceExclusion => ({ path, reason, match: "exact" })),
  ].sort((a, b) => a.path.localeCompare(b.path) || a.match.localeCompare(b.match));
  return inventoryFrom(entries, configurationGaps(root, configured.sourceFiles, configured.gaps), configured.compilerInputs);
}

/** Rebase the authoritative root inventory for a workspace-scoped scanner invocation. */
export function productSourceInventoryForScope(
  root: string,
  scope: string,
  rootInventory: ProductSourceInventory = productSourceInventory(root),
): ProductSourceInventory {
  const absoluteRoot = resolve(root);
  const absoluteScope = resolve(scope);
  const relativeScope = relative(absoluteRoot, absoluteScope);
  if (relativeScope === "") return rootInventory;
  const scopePath = posix(relativeScope);
  if (scopePath === ".." || scopePath.startsWith("../") || resolve(absoluteRoot, scopePath) !== absoluteScope) {
    throw new Error(`Source inventory scope must be inside its root: ${absoluteScope}`);
  }

  const local = productSourceInventory(absoluteScope, rootInventory.compilerInputs);
  const inherited = rootInventory.excludedDirectories.flatMap((entry): SourceExclusion[] => {
    if (entry.match === "any-depth") return [entry];
    if (entry.path === ".") return entry.match === "anchored" ? [entry] : [];
    if (entry.match === "anchored" && (entry.path === scopePath || scopePath.startsWith(`${entry.path}/`))) return [{ ...entry, path: "." }];
    if (!entry.path.startsWith(`${scopePath}/`)) return [];
    return [{ ...entry, path: entry.path.slice(scopePath.length + 1) }];
  });
  const byPath = new Map<string, SourceExclusion>();
  for (const entry of [...local.excludedDirectories, ...inherited]) {
    const key = entry.match === "exact" ? `exact\0${entry.path}` : entry.path;
    const prior = byPath.get(key);
    if (!prior || prior.match === entry.match || entry.match === "any-depth") byPath.set(key, entry);
  }
  const entries = [...byPath.values()].sort((a, b) => a.path.localeCompare(b.path) || a.match.localeCompare(b.match));

  const rootGaps = rootInventory.unresolvedConfigurations.flatMap((gap): SourceInventoryGap[] => {
    const absoluteGap = resolve(absoluteRoot, ...gap.path.split("/"));
    const gapRelativeToScope = relative(absoluteScope, absoluteGap);
    const scopeRelativeToConfigDir = relative(dirname(absoluteGap), absoluteScope);
    const gapIsInsideScope = gapRelativeToScope === "" || (!gapRelativeToScope.startsWith(`..${sep}`) && gapRelativeToScope !== ".." && !gapRelativeToScope.startsWith("/"));
    const configCanGovernScope = scopeRelativeToConfigDir === "" || (!scopeRelativeToConfigDir.startsWith(`..${sep}`) && scopeRelativeToConfigDir !== ".." && !scopeRelativeToConfigDir.startsWith("/"));
    if (!gapIsInsideScope && !configCanGovernScope) return [];
    return [{ ...gap, path: posix(gapRelativeToScope) }];
  });
  const gaps = [...new Map([...local.unresolvedConfigurations, ...rootGaps]
    .map((gap) => [`${gap.path}\0${gap.reason}`, gap])).values()]
    .sort((a, b) => a.path.localeCompare(b.path) || a.reason.localeCompare(b.reason));
  return inventoryFrom(entries, gaps, [...new Set([...rootInventory.compilerInputs, ...local.compilerInputs])]);
}

/** Find an explicitly declared workspace root and retain its inventory when scanning one member. */
export function productSourceInventoryForTarget(scope: string): ProductSourceInventory {
  const absoluteScope = resolve(scope);
  if (existsSync(join(absoluteScope, ".git"))) return productSourceInventory(absoluteScope);
  let candidate = dirname(absoluteScope);
  for (;;) {
    const hasWorkspaceDeclaration = existsSync(join(candidate, "pnpm-workspace.yaml"))
      || existsSync(join(candidate, "pnpm-workspace.yml"))
      || (() => {
        const pkg = readJson(join(candidate, "package.json"));
        return pkg?.workspaces !== undefined;
      })();
    if (hasWorkspaceDeclaration) {
      const inventory = discoverWorkspaceInventory(candidate);
      const ownsScope = inventory.packages.some((workspace) => workspace.dir !== "."
        && resolve(candidate, ...workspace.dir.split("/")) === absoluteScope);
      if (ownsScope) {
        const rootInventory = productSourceInventoryForTarget(candidate);
        return productSourceInventoryForScope(candidate, absoluteScope, rootInventory);
      }
    }
    if (existsSync(join(candidate, ".git"))) break;
    const parent = dirname(candidate);
    if (parent === candidate) break;
    candidate = parent;
  }
  return productSourceInventory(absoluteScope);
}
