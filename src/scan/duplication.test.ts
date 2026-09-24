import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
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

  it("applies anchored inventory exclusions before clone partitioning without excluding a nested lookalike", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-jscpd-anchored-"));
    dirs.push(root);
    const block = `export function summarize(values: number[]) {
  let subtotal = 0;
  for (const value of values) subtotal += value;
  const doubled = subtotal * 2;
  const rounded = Math.round(doubled * 100) / 100;
  return { subtotal, doubled, rounded, count: values.length };
}
`;
    for (const path of [
      "optional/overlay/one.ts",
      "optional/overlay/two.ts",
      "nested/optional/overlay/one.ts",
      "nested/optional/overlay/two.ts",
    ]) {
      mkdirSync(join(root, path, ".."), { recursive: true });
      writeFileSync(join(root, path), block);
    }

    const report = runJscpd(root, {
      timeoutMs: 5_000,
      sourceFileCount: () => 2,
      ignoreGlobs: ["optional/overlay/**"],
    });
    expect(report.duplicates.some((duplicate) => {
      return duplicate.firstFile.name.startsWith("nested/optional/overlay/")
        && duplicate.secondFile.name.startsWith("nested/optional/overlay/");
    })).toBe(true);
    expect(report.duplicates.some((duplicate) => {
      return duplicate.firstFile.name.startsWith("optional/overlay/")
        || duplicate.secondFile.name.startsWith("optional/overlay/");
    })).toBe(false);
  });

  it("rejects an existing malformed jscpd config instead of replacing it with a valid generated config", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-jscpd-malformed-"));
    dirs.push(root);
    writeFileSync(join(root, "package.json"), "{}\n");
    writeFileSync(join(root, ".jscpd.json"), '{"ignore": [ BROKEN }\n');
    expect(() => runJscpd(root, {
      timeoutMs: 5_000,
      sourceFileCount: () => 2,
      jscpdBin: "/must/not/be/invoked",
    })).toThrow(/Invalid \.jscpd\.json/);
  });

  it.each([
    ["scalar", "src/one.ts"],
    ["number", 3],
    ["mixed array", [{}, "src/one.ts"]],
  ])("rejects a %s jscpd ignore instead of silently coercing it", (_label, ignore) => {
    const root = mkdtempSync(join(tmpdir(), "harvey-jscpd-ignore-shape-"));
    dirs.push(root);
    writeFileSync(join(root, "package.json"), "{}\n");
    writeFileSync(join(root, ".jscpd.json"), JSON.stringify({ ignore }));
    expect(() => runJscpd(root, {
      timeoutMs: 5_000,
      sourceFileCount: () => 2,
      jscpdBin: "/must/not/be/invoked",
    })).toThrow(/Invalid jscpd ignore configuration/);
  });
});

describe("runJscpd native failure and cleanup contracts (#2102)", () => {
  function invocation(mode: "valid" | "missing" | "malformed" | "nonzero" | "timeout", files = 2) {
    const root = mkdtempSync(join(tmpdir(), "harvey-jscpd-failure-"));
    dirs.push(root);
    const capture = join(root, "observed-output.json");
    for (let index = 0; index < files; index += 1) writeFileSync(join(root, `${index}.ts`), `export const value${index} = ${index};\n`);
    const executable = join(root, "jscpd.cjs");
    writeFileSync(executable, `#!/usr/bin/env node
const fs=require('node:fs');const path=require('node:path');
const args=process.argv.slice(2);const out=args[args.indexOf('--output')+1];
fs.writeFileSync(${JSON.stringify(capture)},JSON.stringify({out,pid:process.pid}));
const mode=${JSON.stringify(mode)};
if(mode==='valid')fs.writeFileSync(path.join(out,'jscpd-report.json'),JSON.stringify({statistics:{total:{percentage:50,duplicatedLines:12,lines:24}},duplicates:[{format:'typescript',lines:12,tokens:80,fragment:'planted clone',firstFile:{name:path.join(process.cwd(),'0.ts'),start:1,end:12},secondFile:{name:'1.ts',start:1,end:12}}]}));
if(mode==='malformed')fs.writeFileSync(path.join(out,'jscpd-report.json'),'{broken JSON');
if(mode==='nonzero'){process.stderr.write('jscpd native failure canary');process.exitCode=7;}
if(mode==='timeout')setInterval(()=>{},1000);
`);
    chmodSync(executable, 0o755);
    let result: ReturnType<typeof runJscpd> | undefined;
    let error: unknown;
    try {
      result = runJscpd(root, { timeoutMs: mode === "timeout" ? 300 : 5_000, sourceFileCount: () => files, jscpdBin: executable });
    } catch (cause) { error = cause; }
    const observed = JSON.parse(readFileSync(capture, "utf8")) as { out: string; pid: number };
    // Retain a test-owned cleanup fallback so a deliberate cleanup mutation cannot leak scratch.
    dirs.push(observed.out);
    expect(existsSync(observed.out)).toBe(false);
    expect(() => process.kill(observed.pid, 0)).toThrow();
    return { result, error, root: realpathSync(root) };
  }

  it("normalizes the actual child report's clone identity and cleans its output", () => {
    const { result, error, root } = invocation("valid");
    expect(error).toBeUndefined();
    expect(result?.duplicates).toEqual([{ format: "typescript", lines: 12, tokens: 80, fragment: "planted clone", firstFile: { name: "0.ts", start: 1, end: 12 }, secondFile: { name: "1.ts", start: 1, end: 12 } }]);
    expect(JSON.stringify(result)).not.toContain(root);
  });

  it("rejects a successful child with no report when real comparable sources exist", () => {
    const { result, error } = invocation("missing");
    expect(result).toBeUndefined();
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/2.*source|source.*2/i);
  });

  it("preserves the documented clean zero for a genuinely tiny population", () => {
    const { result, error } = invocation("missing", 1);
    expect(error).toBeUndefined();
    expect(result).toEqual({ statistics: { total: { percentage: 0, duplicatedLines: 0, lines: 0 } }, duplicates: [] });
  });

  it("rejects malformed report JSON rather than returning clean results", () => {
    const { result, error } = invocation("malformed");
    expect(result).toBeUndefined();
    expect(error).toBeInstanceOf(SyntaxError);
  });

  it("retains the native nonzero status and stderr", () => {
    const { result, error } = invocation("nonzero");
    expect(result).toBeUndefined();
    expect(error).toMatchObject({ status: 7, signal: null });
    expect((error as { stderr: Buffer }).stderr.toString()).toBe("jscpd native failure canary");
  });

  it("retains the native timeout code and kill signal and removes scratch after close", () => {
    const { result, error } = invocation("timeout");
    expect(result).toBeUndefined();
    expect(error).toMatchObject({ code: "ETIMEDOUT", signal: "SIGKILL" });
  });
});
