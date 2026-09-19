// Product-source inventory shared by scanners that need to distinguish authored paths from
// dependency stores and configured build output. Directory names such as `reports`, `dist`, and
// `vendor` are not evidence by themselves: a product can legitimately author code below each.

import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, join, normalize, relative, resolve, sep } from "node:path";
import ts from "typescript";
import { readEntriesSafe } from "./fs-walk.js";
import { discoverWorkspaceInventory } from "./workspaces.js";

export interface SourceExclusion {
  path: string;
  reason: string;
  match: "anchored" | "any-depth";
}

export interface SourceInventoryGap {
  path: string;
  reason: string;
}

export interface ProductSourceInventory {
  excludedDirectories: readonly SourceExclusion[];
  unresolvedConfigurations: readonly SourceInventoryGap[];
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
export function readStaticConfigObject(path: string): { value?: Record<string, unknown>; error?: string; executable?: boolean } {
  if ([".json", ".jsonc"].includes(extname(path))) return { ...readJsonc(path), executable: false };
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
    if (!expression) return { error: "no static default/module.exports object" };
    const value = staticValue(expression);
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? { value: value as Record<string, unknown>, executable }
      : { error: "export is not a fully static object" };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
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

function configuredOutputDirectories(root: string, pkg: Record<string, unknown> | undefined): Record<string, string> {
  const exclusions: Record<string, string> = {};
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
      const config = readStaticConfigObject(viteConfig);
      if (!config.value) output = undefined;
      else if (config.value.build !== undefined) {
        const build = config.value.build;
        output = typeof build === "object" && build !== null && !Array.isArray(build)
          ? ((build as Record<string, unknown>).outDir === undefined ? "dist" : (build as Record<string, unknown>).outDir as string | undefined)
          : undefined;
      }
    }
    addRelativeDirectory(exclusions, output, "Vite build output declared by Vite configuration");
  }

  const tsconfigs: string[] = [];
  const packages: string[] = [join(root, "package.json")];
  const composerConfigs: string[] = [];
  const goModules: string[] = [];
  const npmrcConfigs: string[] = [];
  const collectConfigs = (dir: string): void => {
    for (const entry of readEntriesSafe(dir).entries) {
      if (entry.isDirectory) {
        if (!Object.hasOwn(alwaysExcluded, entry.name) && !Object.hasOwn(exclusions, entry.name)) collectConfigs(entry.path);
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
  collectConfigs(root);
  for (const configPath of tsconfigs) {
    const resolvedOutput = resolveTsOutput(configPath);
    if (!resolvedOutput.output || !resolvedOutput.declaredAt) continue;
    const base = relative(root, dirname(resolvedOutput.declaredAt));
    addRelativeDirectory(exclusions, join(base, resolvedOutput.output), `TypeScript compiler output declared by ${relative(root, resolvedOutput.declaredAt).split(sep).join("/")}`);
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
        const config = readStaticConfigObject(workspaceViteConfig);
        if (!config.value) output = undefined;
        else if (config.value.build !== undefined) {
          const build = config.value.build;
          output = typeof build === "object" && build !== null && !Array.isArray(build)
            ? ((build as Record<string, unknown>).outDir === undefined ? "dist" : (build as Record<string, unknown>).outDir as string | undefined)
            : undefined;
        }
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
  return exclusions;
}

function configurationGaps(root: string): SourceInventoryGap[] {
  const gaps: SourceInventoryGap[] = [];
  const visit = (dir: string): void => {
    for (const entry of readEntriesSafe(dir).entries) {
      const rel = posix(relative(root, entry.path));
      if (entry.isDirectory) {
        if (!FIXED_BOUNDARIES.some((boundary) => matchesExclusion(boundary, rel))) visit(entry.path);
        continue;
      }
      if (VITE_CONFIG_NAMES.includes(entry.name) || STRYKER_CONFIG_NAMES.includes(entry.name)) {
        const parsed = readStaticConfigObject(entry.path);
        if (!parsed.value) gaps.push({ path: rel, reason: `configuration output paths are unresolved: ${parsed.error}` });
        else if (VITE_CONFIG_NAMES.includes(entry.name) && parsed.value.build !== undefined) {
          const build = parsed.value.build;
          if (typeof build !== "object" || build === null || Array.isArray(build)) gaps.push({ path: rel, reason: "Vite build configuration is not a static object" });
          else if ((build as Record<string, unknown>).outDir !== undefined && typeof (build as Record<string, unknown>).outDir !== "string") {
            gaps.push({ path: rel, reason: "Vite build.outDir is not a static string" });
          }
        }
      } else if (/^tsconfig(?:\.[\w.-]+)?\.json$/.test(entry.name)) {
        const parsed = readJsonc(entry.path);
        if (!parsed.value) gaps.push({ path: rel, reason: `TypeScript configuration is not statically readable: ${parsed.error}` });
        else if (parsed.value.extends !== undefined && (typeof parsed.value.extends !== "string" || (!parsed.value.extends.startsWith(".") && !parsed.value.extends.startsWith("/")))) {
          gaps.push({ path: rel, reason: "TypeScript extends output is unresolved because the base is not a relative/absolute static file" });
        }
      } else if (entry.name === ".npmrc") {
        const text = readFileSync(entry.path, "utf8");
        const storeLine = text.split(/\r?\n/).map((line) => line.trim()).find((line) => /^(?:store-dir|storeDir)\s*=/.test(line));
        if (storeLine && /\$\{|%[^%]+%/.test(storeLine)) gaps.push({ path: rel, reason: "pnpm store-dir contains a dynamic environment reference" });
      }
    }
  };
  visit(root);
  return gaps.sort((a, b) => a.path.localeCompare(b.path) || a.reason.localeCompare(b.reason));
}

function matchesExclusion(exclusion: SourceExclusion, path: string): boolean {
  const normalized = posix(path);
  if (exclusion.match === "anchored") {
    if (exclusion.path === ".") return true;
    return normalized === exclusion.path || normalized.startsWith(`${exclusion.path}/`);
  }
  return normalized.split("/").includes(exclusion.path);
}

function inventoryFrom(
  entries: readonly SourceExclusion[],
  unresolvedConfigurations: readonly SourceInventoryGap[],
): ProductSourceInventory {
  const exclusionsFor = (path: string): readonly SourceExclusion[] => entries.filter((entry) => matchesExclusion(entry, path));
  return {
    excludedDirectories: entries,
    unresolvedConfigurations,
    exclusionsFor,
    excludedDirectoryFor: (path: string) => exclusionsFor(path)[0],
    jscpdIgnoreGlobs: entries.map((entry) => entry.path === "." ? "**/*" : entry.match === "any-depth" ? `**/${entry.path}/**` : `${entry.path}/**`),
  };
}

/** Build the explicit product boundary from package and tool configuration. */
export function productSourceInventory(root: string): ProductSourceInventory {
  const pkg = readJson(join(root, "package.json"));
  const configured = configuredOutputDirectories(root, pkg);
  const entries: SourceExclusion[] = [
    ...FIXED_BOUNDARIES,
    ...Object.entries(configured).map(([path, reason]): SourceExclusion => ({
      path,
      reason,
      match: path === ".pnpm-store" || path === ".pnpm" ? "any-depth" : "anchored",
    })),
  ].sort((a, b) => a.path.localeCompare(b.path) || a.match.localeCompare(b.match));
  return inventoryFrom(entries, configurationGaps(root));
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

  const local = productSourceInventory(absoluteScope);
  const inherited = rootInventory.excludedDirectories.flatMap((entry): SourceExclusion[] => {
    if (entry.match === "any-depth") return [entry];
    if (entry.path === ".") return [entry];
    if (entry.path === scopePath || scopePath.startsWith(`${entry.path}/`)) return [{ ...entry, path: "." }];
    if (!entry.path.startsWith(`${scopePath}/`)) return [];
    return [{ ...entry, path: entry.path.slice(scopePath.length + 1) }];
  });
  const byPath = new Map<string, SourceExclusion>();
  for (const entry of [...local.excludedDirectories, ...inherited]) {
    const prior = byPath.get(entry.path);
    if (!prior || prior.match === entry.match || entry.match === "any-depth") byPath.set(entry.path, entry);
  }
  const entries = [...byPath.values()].sort((a, b) => a.path.localeCompare(b.path) || a.match.localeCompare(b.match));

  const rootGaps = rootInventory.unresolvedConfigurations.map((gap): SourceInventoryGap => ({
    ...gap,
    path: posix(relative(absoluteScope, resolve(absoluteRoot, ...gap.path.split("/")))),
  }));
  const gaps = [...new Map([...local.unresolvedConfigurations, ...rootGaps]
    .map((gap) => [`${gap.path}\0${gap.reason}`, gap])).values()]
    .sort((a, b) => a.path.localeCompare(b.path) || a.reason.localeCompare(b.reason));
  return inventoryFrom(entries, gaps);
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
