import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { productSourceInventory } from "../source-inventory.js";
import { runJscpd } from "./duplication.js";

const dirs: string[] = [];
afterEach(() => {
  delete process.env.HARVEY_JSCPD_CAPTURE;
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("runJscpd product-boundary transport (#2132)", () => {
  it("keeps target-derived output paths in the generated config file and off process argv", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-jscpd-transport-"));
    dirs.push(root);
    const target = join(root, "target");
    mkdirSync(join(target, "src"), { recursive: true });
    writeFileSync(join(target, "package.json"), "{}\n");
    writeFileSync(join(target, "vite.config.ts"), `export default { build: { outDir: "credential-shaped-output" } };\n`);
    writeFileSync(join(target, "src", "a.ts"), "export const a = 1;\n");
    writeFileSync(join(target, "src", "b.ts"), "export const b = 1;\n");

    const capture = join(root, "capture.json");
    const fake = join(root, "jscpd.cjs");
    writeFileSync(fake, `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const args = process.argv.slice(2);
const configPath = args[args.indexOf("--config") + 1];
const output = args[args.indexOf("--output") + 1];
fs.writeFileSync(process.env.HARVEY_JSCPD_CAPTURE, JSON.stringify({ args, config: JSON.parse(fs.readFileSync(configPath, "utf8")) }));
fs.writeFileSync(path.join(output, "jscpd-report.json"), JSON.stringify({ statistics: { total: { percentage: 0, duplicatedLines: 0, lines: 2 } }, duplicates: [] }));
`);
    chmodSync(fake, 0o755);
    process.env.HARVEY_JSCPD_CAPTURE = capture;

    const inventory = productSourceInventory(target);
    runJscpd(target, { timeoutMs: 5_000, sourceFileCount: () => 2, jscpdBin: fake, ignoreGlobs: inventory.jscpdIgnoreGlobs });
    const observed = JSON.parse(readFileSync(capture, "utf8")) as { args: string[]; config: { ignore: string[] } };
    expect(observed.args).toContain("--config");
    expect(observed.args).not.toContain("--ignore");
    expect(observed.args.join(" ")).not.toContain("credential-shaped-output");
    expect(observed.config.ignore.some((glob) => glob.includes("credential-shaped-output"))).toBe(true);
  });
});
