import { readFileSync } from "node:fs";
import { dirname, isAbsolute, join, matchesGlob, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { expect, it } from "vitest";
import { parse } from "yaml";
import { readRecursiveSafe } from "../src/fs-walk.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const site = join(root, "site");

function selected(path: string, patterns: string[]): boolean {
  let included = false;
  for (const pattern of patterns) {
    const negative = pattern.startsWith("!");
    if (matchesGlob(path, negative ? pattern.slice(1) : pattern)) included = !negative;
  }
  return included;
}

it("schedules the production site build for every shared import and toolchain input", () => {
  const config = ts.readConfigFile(join(site, "tsconfig.json"), ts.sys.readFile);
  expect(config.error).toBeUndefined();
  const { options } = ts.parseJsonConfigFileContent(config.config, ts.sys, site);
  const roots = readRecursiveSafe(join(site, "app"))
    .filter((path) => /\.[cm]?[jt]sx?$/.test(path) && !/\.(?:test|spec)\./.test(path))
    .map((path) => join(site, "app", path));
  expect(roots.length).toBeGreaterThan(0);
  // TypeScript follows transitive source imports, including emitted .js specifiers.
  // The build typechecks too, so type-only local dependencies also belong here.
  const program = ts.createProgram(roots, options);
  const shared = program.getSourceFiles().map((source) => relative(root, source.fileName))
    .filter((path) => !isAbsolute(path) && !path.startsWith("../")
      && !path.startsWith("site/") && !path.split("/").includes("node_modules"));
  expect(shared).toContain("src/audit-prerequisites.ts");
  expect(shared).toContain("src/engagement-requirements.ts");
  const inputs = [...new Set([...shared, ".nvmrc", "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"])];
  const workflow = parse(readFileSync(join(root, ".github/workflows/site-ci.yml"), "utf8")) as {
    on: Record<"pull_request" | "push", { paths: string[] }>;
  };
  for (const event of ["pull_request", "push"] as const) {
    const patterns = workflow.on[event].paths;
    expect(inputs.filter((path) => !selected(path, patterns)), `${event} misses site build inputs`).toEqual([]);
    expect(selected("docs/unrelated.md", patterns)).toBe(false);
    // The old site-only routing must fail for a real discovered shared dependency.
    expect(inputs.some((path) => !selected(path, ["site/**", "pnpm-lock.yaml", "pnpm-workspace.yaml"]))).toBe(true);
  }
});
