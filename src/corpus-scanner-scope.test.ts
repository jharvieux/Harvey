import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { countCorpusScannerUnits } from "./corpus-scanner-scope.js";

describe("corpus scanner examined-unit census", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("counts tracked target files without traversing an installed dependency tree", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-scope-"));
    dirs.push(dir);
    execFileSync("git", ["init", "-q", dir]);
    writeFileSync(join(dir, "package.json"), "{}\n");
    mkdirSync(join(dir, "src"));
    writeFileSync(join(dir, "src", "app.ts"), "export const app = true;\n");
    writeFileSync(join(dir, "ignored.fixture"), "tracked but no scanner reads this extension\n");
    execFileSync("git", ["-C", dir, "add", "package.json", "src/app.ts", "ignored.fixture"]);
    mkdirSync(join(dir, "node_modules", "dependency"), { recursive: true });
    for (let index = 0; index < 100; index++) writeFileSync(join(dir, "node_modules", "dependency", `file-${index}.js`), "module.exports = true;\n");

    expect(countCorpusScannerUnits(dir)).toBe(2);
  });

  it("falls back to source-like files while excluding generated and dependency trees", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-scope-fallback-"));
    dirs.push(dir);
    mkdirSync(join(dir, "src"));
    writeFileSync(join(dir, "src", "app.ts"), "export const app = true;\n");
    mkdirSync(join(dir, "node_modules", "dependency"), { recursive: true });
    writeFileSync(join(dir, "node_modules", "dependency", "ignored.js"), "module.exports = true;\n");
    mkdirSync(join(dir, "dist"));
    writeFileSync(join(dir, "dist", "ignored.js"), "module.exports = true;\n");

    expect(countCorpusScannerUnits(dir)).toBe(1);
  });
});
