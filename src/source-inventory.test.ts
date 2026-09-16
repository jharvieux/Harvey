import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { productSourceInventory } from "./source-inventory.js";

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
});
