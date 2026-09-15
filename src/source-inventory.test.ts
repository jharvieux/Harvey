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
});
