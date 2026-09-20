import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadSourceInventory, loadSources } from "./detectors/load-sources.js";
import { measureCodebaseSize } from "./scan/codebase-size.js";
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

  it.each([false, true])("retains transitive compiler inputs below outDir when noEmit is %s", (noEmit) => {
    const root = fixture({
      "tsconfig.json": JSON.stringify({
        compilerOptions: { target: "ES2022", module: "ESNext", rootDir: ".", outDir: "src", noEmit },
        files: ["outside.ts"],
      }),
      "outside.ts": "export { authored } from './src/authored.js';\n",
      "src/authored.ts": "export const authored = true;\n",
    });
    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("src/authored.ts")).toBeUndefined();
    expect(loadSourceInventory(root).map((source) => source.path)).toEqual(["outside.ts", "src/authored.ts"]);
    const scope = resolveScanScope(root);
    try {
      expect(existsSync(join(scope.scanDir, "src/authored.ts"))).toBe(true);
    } finally {
      scope.cleanup();
    }
  });

  it("unions compiler inputs across configs before applying directory or exact output exclusions", () => {
    const root = fixture({
      "tsconfig.build.json": JSON.stringify({ compilerOptions: { rootDir: ".", outDir: "src" }, files: ["outside.ts"] }),
      "tsconfig.check.json": JSON.stringify({ compilerOptions: { noEmit: true, allowJs: true }, files: ["src/authored.ts", "src/outside.js"] }),
      "outside.ts": "export const outside = true;\n",
      "src/authored.ts": "export const authored = true;\n",
      "src/outside.js": "export const handwritten = true;\n",
    });
    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("src")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("src/authored.ts")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("src/outside.js")).toBeUndefined();
    expect(loadSourceInventory(root).map((source) => source.path)).toEqual(["outside.ts", "src/authored.ts", "src/outside.js"]);
    expect(inventory.unresolvedConfigurations).toContainEqual(expect.objectContaining({
      path: "tsconfig.build.json",
      reason: expect.stringContaining("overlaps 2 effective compiler input file(s)"),
    }));
  });

  it("keeps a root checker's compiler inputs when a direct workspace scan rebases a local build", () => {
    const root = fixture({
      "package.json": JSON.stringify({ private: true, workspaces: ["apps/*"] }),
      "tsconfig.check.json": JSON.stringify({ compilerOptions: { noEmit: true }, files: ["apps/web/src/authored.ts"] }),
      "apps/web/package.json": JSON.stringify({ name: "web", private: true }),
      "apps/web/tsconfig.build.json": JSON.stringify({ compilerOptions: { rootDir: ".", outDir: "src" }, files: ["outside.ts"] }),
      "apps/web/outside.ts": "export const outside = true;\n",
      "apps/web/src/authored.ts": "export const authored = true;\n",
      "apps/web/src/outside.js": "export const outside = true;\n",
    });
    const rootInventory = productSourceInventory(root);
    const app = join(root, "apps/web");
    for (const inventory of [productSourceInventoryForScope(root, app, rootInventory), productSourceInventoryForTarget(app)]) {
      expect(inventory.excludedDirectoryFor("src/authored.ts")).toBeUndefined();
      expect(inventory.excludedDirectoryFor("src/outside.js")).toMatchObject({ match: "exact" });
      expect(inventory.unresolvedConfigurations).toContainEqual(expect.objectContaining({
        path: "tsconfig.build.json",
        reason: expect.stringContaining("overlaps 1 effective compiler input file(s)"),
      }));
    }
  });

  it("uses a referenced config's inputs even when its filename is not a tsconfig discovery pattern", () => {
    const root = fixture({
      "tsconfig.json": JSON.stringify({ files: [], references: [{ path: "./config/check.json" }] }),
      "tsconfig.build.json": JSON.stringify({ compilerOptions: { outDir: "src", rootDir: "." }, files: ["outside.ts"] }),
      "config/check.json": JSON.stringify({ compilerOptions: { noEmit: true }, files: ["../src/authored.ts"] }),
      "outside.ts": "export const outside = true;\n",
      "src/authored.ts": "export const authored = true;\n",
      "src/outside.js": "export const outside = true;\n",
    });
    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("src/authored.ts")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("src/outside.js")).toMatchObject({ match: "exact" });
  });

  it("follows an explicit outside project reference that owns an in-scope input", () => {
    const root = fixture({
      "project/tsconfig.json": JSON.stringify({ files: [], references: [{ path: "../config/check.json" }] }),
      "project/tsconfig.build.json": JSON.stringify({ compilerOptions: { outDir: "src", rootDir: "." }, files: ["outside.ts"] }),
      "config/check.json": JSON.stringify({ compilerOptions: { noEmit: true }, files: ["../project/src/authored.ts"] }),
      "project/outside.ts": "export const outside = true;\n",
      "project/src/authored.ts": "export const authored = true;\n",
      "project/src/outside.js": "export const outside = true;\n",
    });
    const inventory = productSourceInventory(join(root, "project"));
    expect(inventory.excludedDirectoryFor("src/authored.ts")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("src/outside.js")).toMatchObject({ match: "exact" });
  });

  it("honors blocked emission and a distinct declarationDir without writing to the audited source", () => {
    const root = fixture({
      "tsconfig.build.json": JSON.stringify({
        compilerOptions: { declaration: true, emitDeclarationOnly: true, declarationDir: "types", outDir: "src", rootDir: "." },
        files: ["outside.ts", "src/authored.ts"],
      }),
      "tsconfig.check.json": JSON.stringify({ compilerOptions: { noEmit: true }, files: ["types/authored.ts"] }),
      "outside.ts": "export const outside = true;\n",
      "src/authored.ts": "export const authored = true;\n",
      "types/authored.ts": "export const handwritten = true;\n",
      "types/outside.d.ts": "export declare const outside: true;\n",
      "types/src/authored.d.ts": "export declare const authored: true;\n",
      "src/outside.js": "export const unproven = true;\n",
    });
    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("types/authored.ts")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("types/outside.d.ts")).toMatchObject({ match: "exact" });
    expect(inventory.excludedDirectoryFor("types/src/authored.d.ts")).toMatchObject({ match: "exact" });
    expect(inventory.excludedDirectoryFor("src/outside.js")).toBeUndefined();
    expect(existsSync(join(root, "src/src/authored.js"))).toBe(false);

    writeFileSync(join(root, "tsconfig.build.json"), JSON.stringify({
      compilerOptions: { noEmitOnError: true, outDir: "src", rootDir: "." }, files: ["outside.ts"],
    }));
    writeFileSync(join(root, "outside.ts"), "export const outside: string = 1;\n");
    const blocked = productSourceInventory(root);
    expect(blocked.excludedDirectoryFor("src/outside.js")).toBeUndefined();
    expect(blocked.unresolvedConfigurations).toContainEqual(expect.objectContaining({
      path: "tsconfig.build.json", reason: expect.stringContaining("compiler blocked emission"),
    }));
  });

  it("does not infer emitted artifacts from a noEmit config or omit its imported JavaScript input", () => {
    const root = fixture({
      "tsconfig.json": JSON.stringify({
        compilerOptions: { target: "ES2022", module: "ESNext", rootDir: ".", outDir: "src", noEmit: true, allowJs: true },
        files: ["outside.ts", "src/live.ts"],
      }),
      "outside.ts": "export const outside = true;\n",
      "src/live.ts": "export { handwritten } from './outside.js';\n",
      "src/outside.js": "export const handwritten = true;\n",
      "src/src/live.js": "export const anotherHandwritten = true;\n",
    });
    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectories.filter((entry) => entry.match === "exact")).toEqual([]);
    expect(loadSourceInventory(root).map((source) => source.path)).toEqual([
      "outside.ts", "src/live.ts", "src/outside.js", "src/src/live.js",
    ]);
    const scope = resolveScanScope(root);
    try {
      expect(existsSync(join(scope.scanDir, "src/outside.js"))).toBe(true);
      expect(existsSync(join(scope.scanDir, "src/src/live.js"))).toBe(true);
    } finally {
      scope.cleanup();
    }
  });

  it.each([
    { mode: "noEmit", compilerOptions: { noEmit: true }, extension: "js", emits: false },
    { mode: "ordinary emit", compilerOptions: { noEmit: false }, extension: "js", emits: true },
    { mode: "declaration-only emit", compilerOptions: { declaration: true, emitDeclarationOnly: true }, extension: "d.ts", emits: true },
  ])("preserves effective compiler inputs inside an overlapping outDir for $mode", ({ compilerOptions, extension, emits }) => {
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
    expect(inventory.excludedDirectoryFor(`src/outside.${extension}`)?.match).toBe(emits ? "exact" : undefined);
    expect(inventory.excludedDirectoryFor(`src/src/reports/dead.${extension}`)?.match).toBe(emits ? "exact" : undefined);
    expect(inventory.jscpdIgnoreGlobs.includes(`src/outside.${extension}`)).toBe(emits);
    expect(inventory.jscpdIgnoreGlobs).not.toContain("src/**");
    expect(inventory.unresolvedConfigurations).toContainEqual(expect.objectContaining({
      path: "tsconfig.build.json",
      reason: expect.stringContaining("overlaps 2 effective compiler input file(s)"),
    }));
    expect(loadSourceInventory(root).map((source) => source.path)).toEqual([
      "outside.ts",
      "src/app/api/eval/route.ts",
      "src/reports/dead.ts",
      ...(!emits ? ["src/outside.js", "src/src/app/api/eval/route.js", "src/src/reports/dead.js"] : []),
    ].sort());

    const scope = resolveScanScope(root);
    try {
      expect(existsSync(join(scope.scanDir, "src/app/api/eval/route.ts"))).toBe(true);
      expect(existsSync(join(scope.scanDir, `src/outside.${extension}`))).toBe(!emits);
    } finally {
      scope.cleanup();
    }
  });

  it.each([false, true])("resolves inherited compiler options and rebases outputs for a workspace with noEmit %s", (noEmit) => {
    const root = fixture({
      "package.json": JSON.stringify({ private: true, workspaces: ["apps/*"] }),
      "config/base.json": JSON.stringify({ compilerOptions: { target: "ES2022", module: "ESNext", rootDir: "..", outDir: "../apps/web/src" } }),
      "apps/web/package.json": JSON.stringify({ name: "web", private: true }),
      "apps/web/tsconfig.build.json": JSON.stringify({
        extends: "../../config/base.json",
        compilerOptions: { noEmit },
        files: ["outside.ts", "src/reports/dead.ts"],
      }),
      "apps/web/outside.ts": "export const outside = true;\n",
      "apps/web/src/reports/dead.ts": "export const dead = true;\n",
      "apps/web/src/apps/web/outside.js": "export const generated = true;\n",
      "apps/web/src/apps/web/src/reports/dead.js": "export const generated = true;\n",
    });

    const inventory = productSourceInventoryForTarget(join(root, "apps/web"));
    expect(inventory.excludedDirectoryFor("src/reports/dead.ts")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("src/apps/web/outside.js")?.match).toBe(noEmit ? undefined : "exact");
    expect(inventory.jscpdIgnoreGlobs.includes("src/apps/web/outside.js")).toBe(!noEmit);
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
      "tsconfig.json": JSON.stringify({ compilerOptions: { outDir: "apps/web/packages/leaf/generated" }, files: ["apps/web/packages/leaf/src/index.ts"] }),
      "tsconfig.whole.json": JSON.stringify({ compilerOptions: { outDir: "apps/web/packages/whole" }, files: ["apps/web/packages/leaf/src/index.ts"] }),
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

  it("preserves ordered exact, anchored, and any-depth exclusions through normalized queries", () => {
    const external = fixture({ "generated.ts": "export const generated = true;\n" });
    const root = fixture({
      "package.json": JSON.stringify({ devDependencies: { vite: "1" } }),
      "dist/authored.ts": "export const authored = true;\n",
      "nested/.git/config": "metadata\n",
    });
    symlinkSync(join(external, "generated.ts"), join(root, "dist/external.ts"));

    const inventory = productSourceInventory(root);
    const expected = inventory.exclusionsFor("dist/external.ts");
    expect(expected.map((exclusion) => exclusion.path)).toEqual(["dist", "dist/external.ts"]);
    expect(inventory.exclusionsFor("dist/./external.ts")).toEqual(expected);
    expect(inventory.exclusionsFor("dist/child/../external.ts")).toEqual(expected);
    expect(inventory.exclusionsFor("nested/.git/config").map((exclusion) => exclusion.path)).toEqual([".git"]);
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

  it("excludes a fully staged install overlay while retaining unrelated authored patches", () => {
    const root = fixture({
      "package.json": "{}",
      "optional/install.sh": [
        '#!/usr/bin/env bash',
        'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
        'ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"',
        'OVERLAY_DIR="$SCRIPT_DIR/overlay"',
        'BACKUP_DIR="$ROOT_DIR/.optional-backup"',
        'cp "$ROOT_DIR/live/one.ts" "$BACKUP_DIR/live/one.ts"',
        'cp "$ROOT_DIR/live/two.ts" "$BACKUP_DIR/live/two.ts"',
        'cp "$OVERLAY_DIR/live/one.ts" "$ROOT_DIR/live/one.ts"',
        'cp "$OVERLAY_DIR/live/two.ts" "$ROOT_DIR/live/two.ts"',
        '',
      ].join("\n"),
      "optional/overlay/live/one.ts": "export const optionalOne = true;\n",
      "optional/overlay/live/two.ts": "export const optionalTwo = true;\n",
      "live/one.ts": "export const liveOne = true;\n",
      "live/two.ts": "export const liveTwo = true;\n",
      "patches/authored-one.ts": "export const authoredOne = true;\n",
      "patches/authored-two.ts": "export const authoredTwo = true;\n",
    });

    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("optional/overlay/live/one.ts")).toMatchObject({
      path: "optional/overlay",
      match: "anchored",
      reason: expect.stringContaining("optional/install.sh"),
    });
    expect(inventory.jscpdIgnoreGlobs).toContain("optional/overlay/**");
    expect(inventory.excludedDirectoryFor("live/one.ts")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("patches/authored-one.ts")).toBeUndefined();
  });

  it("excludes external source aliases with a concrete gap across loaders and size measurement", () => {
    const external = fixture({ "one.ts": "export function one() { throw new Error('Not implemented'); }\n", "two.py": "print('external')\n" });
    const root = fixture({ "package.json": "{}", "live.ts": "export const live = true;\n" });
    symlinkSync(external, join(root, "external-dir"));
    symlinkSync(join(external, "one.ts"), join(root, "external-file.ts"));
    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("external-dir/one.ts")).toMatchObject({ match: "anchored" });
    expect(inventory.excludedDirectoryFor("external-file.ts")).toMatchObject({ match: "exact" });
    expect(inventory.unresolvedConfigurations).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "source-alias", path: "external-dir", reason: expect.stringContaining("outside") }),
      expect.objectContaining({ kind: "source-alias", path: "external-file.ts", reason: expect.stringContaining("outside") }),
    ]));
    expect(loadSourceInventory(root).map((file) => file.path)).toEqual(["live.ts"]);
    expect(loadSources(root).map((file) => file.path)).toEqual(["live.ts", "package.json"]);
    expect(measureCodebaseSize(root).files).toBe(1);
  });

  it("bounds directory cycles and preserves configured external package-store exclusions", () => {
    const store = fixture({ "package/index.ts": "export const dependency = true;\n" });
    const root = fixture({ "package.json": "{}", ".npmrc": "store-dir=.cache/store\n", "live.ts": "export const live = true;\n" });
    mkdirSync(join(root, ".cache"));
    symlinkSync(store, join(root, ".cache/store"));
    symlinkSync(".", join(root, "cycle"));
    const inventory = productSourceInventory(root);
    expect(inventory.unresolvedConfigurations).toEqual([
      expect.objectContaining({ kind: "source-alias", path: "cycle", reason: expect.stringContaining("cycle") }),
    ]);
    expect(inventory.excludedDirectoryFor(".cache/store/package/index.ts")?.reason).toContain("store-dir");
    expect(loadSourceInventory(root).map((file) => file.path)).toEqual(["live.ts"]);
  });

  it.each([false, true])("retains compiler-live overlay files and ancestors while excluding inactive siblings (alias %s)", (alias) => {
    const root = fixture({
      "package.json": "{}",
      "tsconfig.json": JSON.stringify({ compilerOptions: { noEmit: true }, files: ["outside.ts"] }),
      "outside.ts": `export { one } from './${alias ? "active-alias" : "optional/overlay/live"}/one.js';\n`,
      "optional/install.sh": [
        'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
        'ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"',
        'OVERLAY_DIR="$SCRIPT_DIR/overlay"',
        'BACKUP_DIR="$ROOT_DIR/.optional-backup"',
        'cp "$ROOT_DIR/live/one.ts" "$BACKUP_DIR/live/one.ts"',
        'cp "$ROOT_DIR/live/two.ts" "$BACKUP_DIR/live/two.ts"',
        'cp "$OVERLAY_DIR/live/one.ts" "$ROOT_DIR/live/one.ts"',
        'cp "$OVERLAY_DIR/live/two.ts" "$ROOT_DIR/live/two.ts"',
      ].join("\n"),
      "optional/overlay/live/one.ts": "export const one = true;\n",
      "optional/overlay/live/two.ts": "export const inactive = true;\n",
      "live/one.ts": "export const originalOne = true;\n",
      "live/two.ts": "export const originalTwo = true;\n",
      "node_modules/pkg/index.ts": "export const dependency = true;\n",
    });
    if (alias) symlinkSync("optional/overlay/live", join(root, "active-alias"));

    const inventory = productSourceInventory(root);
    for (const path of ["optional", "optional/overlay", "optional/overlay/live", "optional/overlay/live/one.ts"]) {
      expect(inventory.excludedDirectoryFor(path)).toBeUndefined();
    }
    expect(inventory.excludedDirectoryFor("optional/overlay/live/two.ts")).toMatchObject({ match: "exact" });
    if (alias) expect(inventory.excludedDirectoryFor("active-alias/two.ts")).toMatchObject({ match: "exact" });
    expect(inventory.excludedDirectoryFor("node_modules/pkg/index.ts")).toMatchObject({ path: "node_modules" });
    expect(inventory.unresolvedConfigurations).toContainEqual(expect.objectContaining({
      path: "optional/overlay", reason: expect.stringContaining("compiler input"),
    }));
    expect(loadSourceInventory(root).map((file) => file.path)).toContain("optional/overlay/live/one.ts");
    const scope = resolveScanScope(root);
    try {
      expect(existsSync(join(scope.scanDir, "optional/overlay/live/one.ts"))).toBe(true);
      expect(existsSync(join(scope.scanDir, "optional/overlay/live/two.ts"))).toBe(false);
    } finally {
      scope.cleanup();
    }
  });

  it("retains compiler input identity reached through an alias inside a configured output", () => {
    const root = fixture({
      "package.json": "{}",
      "tsconfig.json": JSON.stringify({ compilerOptions: { noEmit: true }, files: ["outside.ts"] }),
      "vite.config.ts": "export default { build: { outDir: 'compiled' } };\n",
      "outside.ts": "export { one } from './active-alias/one.js';\n",
      "compiled/one.ts": "export const one = true;\n",
    });
    symlinkSync("compiled", join(root, "active-alias"));
    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("compiled/one.ts")).toBeUndefined();
    expect(loadSourceInventory(root).map((file) => file.path)).toContain("compiled/one.ts");
  });

  it("retains authored files when copy steps target themselves or another file in the same tree", () => {
    const root = fixture({
      "package.json": "{}",
      "install.sh": [
        'ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
        'BACKUP_DIR="$ROOT_DIR/backup"',
        'cp "$ROOT_DIR/patches/self-one.ts" "$BACKUP_DIR/self-one.ts"',
        'cp "$ROOT_DIR/patches/self-two.ts" "$BACKUP_DIR/self-two.ts"',
        'cp "$ROOT_DIR/patches/self-one.ts" "$ROOT_DIR/patches/self-one.ts"',
        'cp "$ROOT_DIR/patches/self-two.ts" "$ROOT_DIR/patches/self-two.ts"',
        'cp "$ROOT_DIR/patches/cross-one.ts" "$BACKUP_DIR/cross-one.ts"',
        'cp "$ROOT_DIR/patches/cross-two.ts" "$BACKUP_DIR/cross-two.ts"',
        'cp "$ROOT_DIR/patches/cross-one.ts" "$ROOT_DIR/patches/cross-two.ts"',
        'cp "$ROOT_DIR/patches/cross-two.ts" "$ROOT_DIR/patches/cross-one.ts"',
      ].join("\n"),
      "backup/.gitkeep": "",
      "patches/self-one.ts": "export const selfOne = true;\n",
      "patches/self-two.ts": "export const selfTwo = true;\n",
      "patches/cross-one.ts": "export const crossOne = true;\n",
      "patches/cross-two.ts": "export const crossTwo = true;\n",
    });

    const inventory = productSourceInventory(root);
    for (const file of ["self-one.ts", "self-two.ts", "cross-one.ts", "cross-two.ts"]) {
      expect(inventory.excludedDirectoryFor(`patches/${file}`)).toBeUndefined();
    }
  });

  it("matches backup provenance through a canonical directory alias", () => {
    const root = fixture({
      "package.json": "{}",
      "install.sh": [
        'ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
        'BACKUP_DIR="$ROOT_DIR/backup"',
        'cp "$ROOT_DIR/live/one.ts" "$BACKUP_DIR/one.ts"',
        'cp "$ROOT_DIR/live/two.ts" "$BACKUP_DIR/two.ts"',
        'cp "$ROOT_DIR/patches/one.ts" "$ROOT_DIR/live-alias/one.ts"',
        'cp "$ROOT_DIR/patches/two.ts" "$ROOT_DIR/live-alias/two.ts"',
      ].join("\n"),
      "backup/.gitkeep": "",
      "live/one.ts": "export const liveOne = true;\n",
      "live/two.ts": "export const liveTwo = true;\n",
      "patches/one.ts": "export const overlayOne = true;\n",
      "patches/two.ts": "export const overlayTwo = true;\n",
    });
    symlinkSync("live", join(root, "live-alias"));

    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("patches/one.ts")).toMatchObject({
      path: "patches",
      reason: expect.stringContaining("install.sh"),
    });
    expect(inventory.excludedDirectoryFor("live/one.ts")).toBeUndefined();
  });

  it("does not infer an overlay from copy flags that may leave the destination unchanged", () => {
    const root = fixture({
      "package.json": "{}",
      "install.sh": [
        'ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
        'BACKUP_DIR="$ROOT_DIR/backup"',
        'cp "$ROOT_DIR/live/one.ts" "$BACKUP_DIR/one.ts"',
        'cp "$ROOT_DIR/live/two.ts" "$BACKUP_DIR/two.ts"',
        'cp -n "$ROOT_DIR/patches/one.ts" "$ROOT_DIR/live/one.ts"',
        'cp -i "$ROOT_DIR/patches/two.ts" "$ROOT_DIR/live/two.ts"',
      ].join("\n"),
      "backup/.gitkeep": "",
      "live/one.ts": "export const liveOne = true;\n",
      "live/two.ts": "export const liveTwo = true;\n",
      "patches/one.ts": "export const authoredOne = true;\n",
      "patches/two.ts": "export const authoredTwo = true;\n",
    });

    const inventory = productSourceInventory(root);
    expect(inventory.excludedDirectoryFor("patches/one.ts")).toBeUndefined();
    expect(inventory.excludedDirectoryFor("patches/two.ts")).toBeUndefined();
  });
});
