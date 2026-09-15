// Product-source inventory shared by scanners that need to distinguish authored paths from
// dependency stores and configured build output. Directory names such as `reports`, `dist`, and
// `vendor` are not evidence by themselves: a product can legitimately author code below each.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, normalize, relative, sep } from "node:path";
import { readEntriesSafe } from "./fs-walk.js";

export interface SourceExclusion {
  path: string;
  reason: string;
}

export interface ProductSourceInventory {
  excludedDirectories: readonly SourceExclusion[];
  excludedDirectoryFor(path: string): SourceExclusion | undefined;
  jscpdIgnoreGlobs: readonly string[];
}

const alwaysExcluded = new Map<string, string>([
  [".git", "Git metadata is repository history, not product source"],
  ["node_modules", "installed package dependencies are not product source"],
]);

function readJson(path: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    return typeof parsed === "object" && parsed !== null ? parsed as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function hasDependency(pkg: Record<string, unknown> | undefined, name: string): boolean {
  if (!pkg) return false;
  return ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"].some((key) => {
    const entries = pkg[key];
    return typeof entries === "object" && entries !== null && name in entries;
  });
}

function addRelativeDirectory(exclusions: Map<string, string>, value: unknown, reason: string): void {
  if (typeof value !== "string" || value.length === 0) return;
  const normalized = normalize(value).split(sep).join("/").replace(/^\.\//, "").replace(/\/$/, "");
  if (!normalized || normalized === "." || normalized.startsWith("../") || normalized.startsWith("/")) return;
  exclusions.set(normalized, reason);
}

function configuredOutputDirectories(root: string, pkg: Record<string, unknown> | undefined): Map<string, string> {
  const exclusions = new Map<string, string>();
  const pnpm = existsSync(join(root, "pnpm-lock.yaml")) || existsSync(join(root, "pnpm-workspace.yaml"))
    || (typeof pkg?.packageManager === "string" && pkg.packageManager.startsWith("pnpm@"));
  if (pnpm) {
    exclusions.set(".pnpm-store", "pnpm package store declared by workspace/package-manager metadata");
    exclusions.set(".pnpm", "pnpm package store declared by workspace/package-manager metadata");
  }

  if (existsSync(join(root, "composer.json"))) exclusions.set("vendor", "Composer dependency directory declared by composer.json");
  if (existsSync(join(root, "go.mod"))) exclusions.set("vendor", "Go dependency vendor directory declared by go.mod");

  const scripts = pkg?.scripts;
  const scriptText = typeof scripts === "object" && scripts !== null ? Object.values(scripts).filter((v): v is string => typeof v === "string").join("\n") : "";
  if (/\b(?:vitest|jest|c8|nyc)\b[^\n]*\s--coverage\b/.test(scriptText)) {
    exclusions.set("coverage", "test coverage output declared by package scripts");
  }

  const viteConfig = ["vite.config.ts", "vite.config.js", "vite.config.mjs", "vite.config.cjs", "vite.config.mts", "vite.config.cts"]
    .map((name) => join(root, name))
    .find(existsSync);
  if (viteConfig || hasDependency(pkg, "vite")) {
    let output = "dist";
    if (viteConfig) {
      try {
        const text = readFileSync(viteConfig, "utf8");
        output = text.match(/\boutDir\s*:\s*["']([^"']+)["']/)?.[1] ?? output;
      } catch { /* Preserve Vite's documented default when its config cannot be read. */ }
    }
    addRelativeDirectory(exclusions, output, "Vite build output declared by Vite configuration");
  }

  const tsconfigs: string[] = [];
  const packages: string[] = [join(root, "package.json")];
  const collectConfigs = (dir: string): void => {
    for (const entry of readEntriesSafe(dir).entries) {
      if (entry.isDirectory) {
        if (!alwaysExcluded.has(entry.name) && !exclusions.has(entry.name)) collectConfigs(entry.path);
      } else if (/^tsconfig(?:\.[\w.-]+)?\.json$/.test(entry.name)) {
        tsconfigs.push(entry.path);
      } else if (entry.name === "package.json" && entry.path !== join(root, "package.json")) {
        packages.push(entry.path);
      }
    }
  };
  collectConfigs(root);
  for (const configPath of tsconfigs) {
    const config = readJson(configPath);
    const compiler = config?.compilerOptions;
    if (typeof compiler !== "object" || compiler === null) continue;
    const output = (compiler as Record<string, unknown>).outDir;
    if (typeof output !== "string") continue;
    const base = relative(root, dirname(configPath));
    addRelativeDirectory(exclusions, join(base, output), `TypeScript compiler output declared by ${relative(root, configPath).split(sep).join("/")}`);
  }

  // Workspace packages can own their own Vite build directory or coverage command. Apply the
  // same evidence rules at each manifest rather than treating a root-level package.json as the
  // entire product configuration.
  for (const packagePath of packages) {
    const workspacePkg = readJson(packagePath);
    if (!workspacePkg) continue;
    const base = relative(root, dirname(packagePath));
    const prefix = base === "" ? "" : `${base}/`;
    const workspaceScripts = workspacePkg.scripts;
    const workspaceScriptText = typeof workspaceScripts === "object" && workspaceScripts !== null
      ? Object.values(workspaceScripts).filter((v): v is string => typeof v === "string").join("\n")
      : "";
    if (/\b(?:vitest|jest|c8|nyc)\b[^\n]*\s--coverage\b/.test(workspaceScriptText)) {
      addRelativeDirectory(exclusions, `${prefix}coverage`, `test coverage output declared by ${base === "" ? "package.json" : `${base}/package.json`}`);
    }
    const workspaceViteConfig = ["vite.config.ts", "vite.config.js", "vite.config.mjs", "vite.config.cjs", "vite.config.mts", "vite.config.cts"]
      .map((name) => join(dirname(packagePath), name))
      .find(existsSync);
    if (workspaceViteConfig || hasDependency(workspacePkg, "vite")) {
      let output = "dist";
      if (workspaceViteConfig) {
        try {
          const text = readFileSync(workspaceViteConfig, "utf8");
          output = text.match(/\boutDir\s*:\s*["']([^"']+)["']/)?.[1] ?? output;
        } catch { /* Preserve Vite's documented default when its config cannot be read. */ }
      }
      addRelativeDirectory(exclusions, join(base, output), `Vite build output declared by ${base === "" ? "package.json" : `${base}/package.json`}`);
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
  return exclusions;
}

/** Build the explicit product boundary from package and tool configuration. */
export function productSourceInventory(root: string): ProductSourceInventory {
  const pkg = readJson(join(root, "package.json"));
  const exclusions = new Map(alwaysExcluded);
  for (const [path, reason] of configuredOutputDirectories(root, pkg)) exclusions.set(path, reason);
  const entries = [...exclusions.entries()]
    .map(([path, reason]) => ({ path, reason }))
    .sort((a, b) => a.path.localeCompare(b.path));
  const ordered = [...entries].sort((a, b) => b.path.length - a.path.length);
  const excludedDirectoryFor = (path: string): SourceExclusion | undefined => {
    const normalized = path.split(sep).join("/").replace(/^\.\//, "").replace(/\/$/, "");
    return ordered.find((entry) => normalized === entry.path || normalized.startsWith(`${entry.path}/`));
  };
  return {
    excludedDirectories: entries,
    excludedDirectoryFor,
    jscpdIgnoreGlobs: entries.map(({ path }) => `**/${path}/**`),
  };
}
