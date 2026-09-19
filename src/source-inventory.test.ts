import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadSourceInventory } from "./detectors/load-sources.js";
import { resolveScanScope } from "./scan/scan-scope.js";
import { productSourceInventory, productSourceInventoryForScope, productSourceInventoryForTarget } from "./source-inventory.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "harvey-source-inventory-"));
  dirs.push(root);
  for (const [path, text] of Object.entries(files)) {
    const full = join(root, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
  }
  return root;
}

describe("productSourceInventory (#2132/#2125)", () => {
  it("excludes a pnpm store and configured Vite output, while retaining authored reports/dist/vendor paths", () => {
    const root = fixture({
      "package.json": JSON.stringify({ packageManager: "pnpm@9.0.0", devDependencies: { vite: "1" } }),
      "apps/main/src/app/api/reports/bookings/route.ts": "export const GET = () => new Response();\n",
      "apps/main/dist/authored-report.ts": "export const report = true;\n",
      "apps/main/vendor/client.ts": "export const client = true;\n",
      ".pnpm-store/v3/pkg/index.ts": "export const cache = true;\n",
      "dist/assets/app.ts": "export const generated = true;\n",
    });
    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor(".pnpm-store/v3/pkg")).toMatchObject({ path: ".pnpm-store" });
    expect(inventory.excludedDirectoryFor("dist/assets")).toMatchObject({ path: "dist" });
    expect(inventory.excludedDirectoryFor("apps/main/src/app/api/reports")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("apps/main/dist")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("apps/main/vendor")).toBeUndefined();
  });

  it("uses an explicit TypeScript output directory without treating every generated-named path as output", () => {
    const root = fixture({
      "tsconfig.json": JSON.stringify({ compilerOptions: { outDir: "build/generated" } }),
      "build/generated/index.js": "exports.generated = true;\n",
      "src/generated/handwritten.ts": "export const authored = true;\n",
      "src/reports/route.ts": "export const GET = () => null;\n",
    });
    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("build/generated")).toMatchObject({ path: "build/generated" });
    expect(inventory.excludedDirectoryFor("src/generated")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("src/reports")).toBeUndefined();
  });

  it.each([
    { mode: "noEmit", compilerOptions: { noEmit: true }, extension: "js" },
    { mode: "ordinary emit", compilerOptions: { noEmit: false }, extension: "js" },
    { mode: "declaration-only emit", compilerOptions: { declaration: true, emitDeclarationOnly: true }, extension: "d.ts" },
  ])("preserves effective compiler inputs inside an overlapping outDir for $mode", ({ compilerOptions, extension }) => {
    const root = fixture({
      "tsconfig.build.json": JSON.stringify({
        compilerOptions: { target: "ES2022", module: "ESNext", rootDir: ".", outDir: "src", ...compilerOptions },
        files: ["outside.ts", "src/app/api/eval/route.ts", "src/reports/dead.ts"],
      }),
      "outside.ts": "export const outside = true;\n",
      "src/app/api/eval/route.ts": "export const GET = () => null;\n",
      "src/reports/dead.ts": "export const dead = true;\n",
      [`src/outside.${extension}`]: "export declare const outside = true;\n",
      [`src/src/app/api/eval/route.${extension}`]: "export declare const GET = true;\n",
      [`src/src/reports/dead.${extension}`]: "export declare const dead = true;\n",
    });

    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("src")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("src/app/api/eval/route.ts")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("src/reports/dead.ts")).toBeUndefined();
    expect(inventory.excludedDirectoryFor(`src/outside.${extension}`)).toMatchObject({ match: "exact" });
    expect(inventory.excludedDirectoryFor(`src/src/reports/dead.${extension}`)).toMatchObject({ match: "exact" });
    expect(inventory.jscpdIgnoreGlobs).toContain(`src/outside.${extension}`);
    expect(inventory.jscpdIgnoreGlobs).not.toContain("src/**");
    expect(inventory.unresolvedConfigurations).toContainEqual(expect.objectContaining({
      path: "tsconfig.build.json",
      reason: expect.stringContaining("overlaps 2 effective compiler input file(s)"),
    }));
    expect(loadSourceInventory(root).map((source) => source.path)).toEqual([
      "outside.ts",
      "src/app/api/eval/route.ts",
      "src/reports/dead.ts",
    ]);

    const scope = resolveScanScope(root);
    try {
      expect(existsSync(join(scope.scanDir, "src/app/api/eval/route.ts"))).toBe(true);
      expect(existsSync(join(scope.scanDir, `src/outside.${extension}`))).toBe(false);
    } finally {
      scope.cleanup();
    }
  });

  it("resolves inherited compiler options before protecting inputs and rebases exact outputs for a workspace", () => {
    const root = fixture({
      "package.json": JSON.stringify({ private: true, workspaces: ["apps/*"] }),
      "config/base.json": JSON.stringify({ compilerOptions: { target: "ES2022", module: "ESNext", rootDir: "..", outDir: "../apps/web/src" } }),
      "apps/web/package.json": JSON.stringify({ name: "web", private: true }),
      "apps/web/tsconfig.build.json": JSON.stringify({
        extends: "../../config/base.json",
        compilerOptions: { noEmit: true },
        files: ["outside.ts", "src/reports/dead.ts"],
      }),
      "apps/web/outside.ts": "export const outside = true;\n",
      "apps/web/src/reports/dead.ts": "export const dead = true;\n",
      "apps/web/src/apps/web/outside.js": "export const generated = true;\n",
      "apps/web/src/apps/web/src/reports/dead.js": "export const generated = true;\n",
    });

    const inventory = productSourceInventoryForTarget(join(root, "apps/web"));
    expect(inventory.excludedDirectoryFor("src/reports/dead.ts")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("src/apps/web/outside.js")).toMatchObject({ match: "exact" });
    expect(inventory.jscpdIgnoreGlobs).toContain("src/apps/web/outside.js");
    expect(inventory.unresolvedConfigurations).toContainEqual(expect.objectContaining({
      path: "tsconfig.build.json",
      reason: expect.stringContaining("effective compiler input"),
    }));
  });

  it("derives each workspace's output boundary from that workspace's manifest", () => {
    const root = fixture({
      "pnpm-workspace.yaml": "packages:\n  - apps/*\n",
      "apps/web/package.json": JSON.stringify({ devDependencies: { vite: "1" } }),
      "apps/web/dist/app.js": "export const output = true;\n",
      "apps/web/src/dist/handwritten.ts": "export const authored = true;\n",
    });
    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("apps/web/dist")).toMatchObject({ path: "apps/web/dist" });
    expect(inventory.excludedDirectoryFor("apps/web/src/dist")).toBeUndefined();
  });

  it("rebases root-declared output and store coordinates for a workspace scanner", () => {
    const root = fixture({
      "package.json": JSON.stringify({ packageManager: "pnpm@9.0.0", workspaces: ["apps/*"] }),
      ".npmrc": "store-dir=apps/web/package-cache\n",
      "tsconfig.json": JSON.stringify({ compilerOptions: { outDir: "apps/web/compiled" } }),
      "vite.config.ts": "const outDir = 'apps/web/vite-output'; export default { build: { outDir } };\n",
      "apps/web/package.json": JSON.stringify({ name: "web", private: true }),
      "apps/web/src/app/reports/authored.ts": "export const authored = true;\n",
      "apps/web/.pnpm-store/v3/pkg/index.ts": "export const dependency = true;\n",
      "apps/web/package-cache/v3/pkg/index.ts": "export const cached = true;\n",
      "apps/web/compiled/index.ts": "export const generated = true;\n",
    });
    const rootInventory = productSourceInventory(root);
    const workspaceInventory = productSourceInventoryForScope(root, join(root, "apps/web"), rootInventory);
    expect(workspaceInventory.excludedDirectoryFor(".pnpm-store/v3/pkg")).toMatchObject({ path: ".pnpm-store", match: "any-depth" });
    expect(workspaceInventory.excludedDirectoryFor("package-cache/v3/pkg")).toMatchObject({ path: "package-cache", reason: expect.stringContaining(".npmrc") });
    expect(workspaceInventory.excludedDirectoryFor("compiled/index.ts")).toMatchObject({ path: "compiled", reason: expect.stringContaining("tsconfig.json") });
    expect(workspaceInventory.excludedDirectoryFor("src/app/reports/authored.ts")).toBeUndefined();
    expect(workspaceInventory.jscpdIgnoreGlobs).toEqual(expect.arrayContaining(["**/.pnpm-store/**", "package-cache/**", "compiled/**"]));
    expect(workspaceInventory.unresolvedConfigurations).toContainEqual(expect.objectContaining({
      path: "../../vite.config.ts",
      reason: expect.stringContaining("configuration output paths are unresolved"),
    }));
    expect(productSourceInventoryForTarget(join(root, "apps/web")).excludedDirectories).toEqual(workspaceInventory.excludedDirectories);
  });

  it("marks direct and nested files excluded when a root output contains the whole workspace", () => {
    const root = fixture({
      "package.json": JSON.stringify({ private: true, workspaces: ["apps/*"] }),
      "tsconfig.json": JSON.stringify({ compilerOptions: { outDir: "apps" } }),
      "apps/web/package.json": JSON.stringify({ name: "web", private: true }),
      "apps/web/generated.ts": "export const direct = true;\n",
      "apps/web/src/generated.ts": "export const nested = true;\n",
    });
    const inventory = productSourceInventoryForTarget(join(root, "apps/web"));
    expect(inventory.excludedDirectoryFor("generated.ts")).toMatchObject({ path: ".", reason: expect.stringContaining("tsconfig.json") });
    expect(inventory.excludedDirectoryFor("src/generated.ts")).toMatchObject({ path: ".", reason: expect.stringContaining("tsconfig.json") });
    expect(inventory.jscpdIgnoreGlobs).toContain("**/*");
  });

  it("preserves root inventory decisions through nested workspace scopes", () => {
    const root = fixture({
      "package.json": JSON.stringify({ private: true, packageManager: "pnpm@9", workspaces: ["apps/*"] }),
      "pnpm-workspace.yaml": "packages:\n  - apps/*\n",
      "tsconfig.json": JSON.stringify({ compilerOptions: { outDir: "apps/web/packages/leaf/generated" } }),
      "tsconfig.whole.json": JSON.stringify({ compilerOptions: { outDir: "apps/web/packages/whole" } }),
      "apps/web/package.json": JSON.stringify({ name: "web", private: true, workspaces: ["packages/*"] }),
      "apps/web/packages/leaf/package.json": JSON.stringify({ name: "leaf", private: true }),
      "apps/web/packages/leaf/generated/out.ts": "export const generated = true;\n",
      "apps/web/packages/leaf/nested/.pnpm-store/v3/pkg/out.ts": "export const cached = true;\n",
      "apps/web/packages/leaf/src/index.ts": "export const authored = true;\n",
      "apps/web/packages/whole/package.json": JSON.stringify({ name: "whole", private: true }),
      "apps/web/packages/whole/root-artifact.ts": "export const generated = true;\n",
    });
    const workspace = join(root, "apps/web");
    const leaf = join(workspace, "packages/leaf");
    const whole = join(workspace, "packages/whole");
    const rootInventory = productSourceInventory(root);
    const workspaceInventory = productSourceInventoryForScope(root, workspace, rootInventory);
    const composedLeaf = productSourceInventoryForScope(workspace, leaf, workspaceInventory);
    const directLeaf = productSourceInventoryForScope(root, leaf, rootInventory);
    const composedWhole = productSourceInventoryForScope(workspace, whole, workspaceInventory);
    const directWhole = productSourceInventoryForScope(root, whole, rootInventory);

    for (const path of ["generated/out.ts", "nested/.pnpm-store/v3/pkg/out.ts", "src/index.ts"]) {
      expect(composedLeaf.exclusionsFor(path)).toEqual(directLeaf.exclusionsFor(path));
      expect(productSourceInventoryForTarget(leaf).exclusionsFor(path)).toEqual(directLeaf.exclusionsFor(path));
    }
    expect(directLeaf.excludedDirectoryFor("generated/out.ts")).toMatchObject({ path: "generated", match: "anchored" });
    expect(directLeaf.excludedDirectoryFor("nested/.pnpm-store/v3/pkg/out.ts")).toMatchObject({ path: ".pnpm-store", match: "any-depth" });
    expect(directLeaf.excludedDirectoryFor("src/index.ts")).toBeUndefined();
    expect(composedWhole.exclusionsFor("root-artifact.ts")).toEqual(directWhole.exclusionsFor("root-artifact.ts"));
    expect(productSourceInventoryForTarget(whole).excludedDirectoryFor("root-artifact.ts")).toMatchObject({ path: "." });
  });

  it("stops inherited inventory at a separate repository root", () => {
    const root = fixture({
      "package.json": JSON.stringify({ private: true, workspaces: ["apps/*"] }),
      "tsconfig.json": JSON.stringify({ compilerOptions: { outDir: "apps" } }),
      "apps/web/.git/config": "[core]\n",
      "apps/web/package.json": JSON.stringify({ name: "separate", private: true }),
      "apps/web/src/index.ts": "export const authored = true;\n",
    });
    expect(productSourceInventoryForTarget(join(root, "apps/web")).excludedDirectoryFor("src/index.ts")).toBeUndefined();
  });

  it("keeps fixed dependency boundaries at any depth and contextual outputs at their authored coordinate", () => {
    const root = fixture({
      "package.json": JSON.stringify({ devDependencies: { vite: "1" } }),
      "dist/generated.js": "export const generated = true;\n",
      "src/app/dist/one.ts": "export const one = true;\n",
      "src/app/dist/two.ts": "export const two = true;\n",
      "apps/web/node_modules/pkg/index.ts": "export const dependency = true;\n",
      "apps/web/nested/.git/config": "metadata\n",
    });
    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("apps/web/node_modules/pkg")).toMatchObject({ path: "node_modules", match: "any-depth" });
    expect(inventory.excludedDirectoryFor("apps/web/nested/.git")).toMatchObject({ path: ".git", match: "any-depth" });
    expect(inventory.excludedDirectoryFor("dist")).toMatchObject({ path: "dist", match: "anchored" });
    expect(inventory.excludedDirectoryFor("src/app/dist")).toBeUndefined();
    expect(inventory.jscpdIgnoreGlobs).toContain("dist/**");
    expect(inventory.jscpdIgnoreGlobs).not.toContain("**/dist/**");
  });

  it("reads JSONC inheritance and workspace package-manager configuration without substring guesses", () => {
    const root = fixture({
      "package.json": "{}",
      "tsconfig.base.json": `{\n // generated output\n "compilerOptions": { "outDir": "compiled", },\n}`,
      "tsconfig.json": `{ "extends": "./tsconfig.base.json" }`,
      "apps/pnpm/package.json": JSON.stringify({ packageManager: "pnpm@9" }),
      "apps/pnpm/.npmrc": "store-dir=.cache/pnpm-store\n",
      "apps/pnpm/.cache/pnpm-store/pkg/index.ts": "export const cached = true;\n",
      "apps/php/composer.json": "{}",
      "apps/php/vendor/pkg/index.ts": "export const vendored = true;\n",
      "apps/go/go.mod": "module example.test/app\n",
      "apps/go/vendor/pkg/index.ts": "export const vendored = true;\n",
    });
    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("compiled/a.js")).toMatchObject({ path: "compiled" });
    expect(inventory.excludedDirectoryFor("apps/pnpm/.cache/pnpm-store/pkg")).toMatchObject({ path: "apps/pnpm/.cache/pnpm-store" });
    expect(inventory.excludedDirectoryFor("apps/php/vendor/pkg")).toMatchObject({ path: "apps/php/vendor" });
    expect(inventory.excludedDirectoryFor("apps/go/vendor/pkg")).toMatchObject({ path: "apps/go/vendor" });
  });

  it("parses literal JS tool outputs and discloses dynamic values without reading comments or strings", () => {
    const root = fixture({
      "package.json": "{}",
      "vite.config.ts": `const out = "secret-shaped-dir";\n// outDir: "comment-only"\nexport default defineConfig({ build: { outDir: out }, note: "outDir: string-only" });\n`,
      "stryker.config.js": `module.exports = { tempDirName: "mutation-tmp", jsonReporter: { fileName: "reports/mutation/result.json" } };\n`,
      "src/comment-only/app.ts": "export const app = true;\n",
      "mutation-tmp/generated.ts": "export const generated = true;\n",
      "reports/mutation/result.json": "{}",
    });
    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("comment-only")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("secret-shaped-dir")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("mutation-tmp/generated.ts")).toMatchObject({ path: "mutation-tmp" });
    expect(inventory.excludedDirectoryFor("reports/mutation")).toMatchObject({ path: "reports/mutation" });
    expect(inventory.unresolvedConfigurations).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: "vite.config.ts", reason: expect.stringContaining("unresolved") }),
    ]));
  });

  it("keeps Vite's default output exclusion when unrelated config fields are dynamic", () => {
    const root = fixture({
      "package.json": JSON.stringify({ devDependencies: { vite: "1" } }),
      "vite.config.js": [
        'const selected = process.env.VITE_ENTRY;',
        'module.exports = { build: { lib: { entry: `src/${selected}.ts` } } };',
        "",
      ].join("\n"),
      "dist/generated.ts": "export const generated = true;\n",
      "src/dist/authored.ts": "export const authored = true;\n",
    });

    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("dist/generated.ts")).toMatchObject({ path: "dist" });
    expect(inventory.excludedDirectoryFor("src/dist/authored.ts")).toBeUndefined();
    expect(inventory.unresolvedConfigurations).not.toContainEqual(expect.objectContaining({ path: "vite.config.js" }));
  });

  it("does not inherit an unresolved sibling config into a direct workspace scan", () => {
    const root = fixture({
      "package.json": JSON.stringify({ private: true, workspaces: ["apps/*"] }),
      "apps/a/package.json": JSON.stringify({ name: "a", private: true }),
      "apps/a/src/index.ts": "export const authored = true;\n",
      "apps/b/package.json": JSON.stringify({ name: "b", private: true }),
      "apps/b/vite.config.ts": "const outDir = process.env.OUT_DIR; export default { build: { outDir } };\n",
    });

    const inventory = productSourceInventoryForTarget(join(root, "apps/a"));
    expect(inventory.excludedDirectoryFor("src/index.ts")).toBeUndefined();
    expect(inventory.unresolvedConfigurations).not.toContainEqual(expect.objectContaining({ path: "../b/vite.config.ts" }));
  });
});
