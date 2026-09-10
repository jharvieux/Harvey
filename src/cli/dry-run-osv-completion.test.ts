import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const providerPaths: string[] = [];
let providerFailure: "none" | "missing" | "invalid" | "omitted" = "none";
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, execFileSync: vi.fn((bin: string, args: string[], options: unknown) => {
    if (bin !== "osv-scanner") return actual.execFileSync(bin as never, args as never, options as never);
    const path = args.at(-1)!;
    providerPaths.push(path);
    if (path.includes("nested") && providerFailure === "missing") throw Object.assign(new Error("missing binary"), { code: "ENOENT" });
    if (path.includes("nested") && providerFailure === "invalid") return "not JSON";
    return JSON.stringify({ results: [{ source: { path }, packages: [
      { package: { name: "chosen", version: "1.0.0", ecosystem: "npm" } },
      ...(path.includes("nested") && providerFailure === "omitted" ? [] : [{ package: { name: "other", version: "2.0.0", ecosystem: "npm" } }]),
    ] }] });
  }) };
});
vi.mock("../scan/secrets.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../scan/secrets.js")>();
  return { ...actual, scanSecrets: vi.fn(() => []), resolveBundleScan: vi.fn(() => ({})) };
});
vi.mock("../scan/semgrep.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../scan/semgrep.js")>();
  return { ...actual, runSemgrep: vi.fn(() => ({ result: { results: [], errors: [], paths: { scanned: [], skipped: [] }, time: { rules: [], fixpoint_timeouts: [] } } })) };
});
const { generateDryRun } = await import("./dry-run.js");
const { validateDryRunFamily } = await import("../dry-run-artifacts.js");
let root: string;
let target: string;
let out: string;
const resolved = { lockfileVersion: 3, packages: { "node_modules/chosen": { version: "1.0.0" }, "node_modules/other": { version: "2.0.0" } } };
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "harvey-dry-run-osv-completion-"));
  target = join(root, "target"); out = join(root, "out"); providerFailure = "none"; providerPaths.length = 0;
  mkdirSync(join(target, "nested"), { recursive: true });
  writeFileSync(join(target, "package.json"), JSON.stringify({ name: "fixture", dependencies: { chosen: "1.0.0", other: "2.0.0" } }));
  writeFileSync(join(target, "package-lock.json"), JSON.stringify(resolved));
  writeFileSync(join(target, "nested/package-lock.json"), JSON.stringify(resolved));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("owning dry-run live OSV completion", () => {
  it("publishes explicit static input gaps from the actual mechanical producer and preserves them in the report", async () => {
    mkdirSync(join(target, "declarations"));
    writeFileSync(join(target, "declarations/package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { chosen: "^1.0.0" } } } }));
    mkdirSync(join(target, "manifest-only"));
    writeFileSync(join(target, "manifest-only/package.json"), JSON.stringify({ dependencies: { chosen: "^1.0.0" } }));
    await generateDryRun(target, out);
    expect(providerPaths).toHaveLength(2);
    expect(providerPaths.some((path) => path.includes("declarations"))).toBe(false);
    const raw = JSON.parse(readFileSync(join(out, "findings.json"), "utf8")) as { id: string; evidence: string }[];
    const report = JSON.parse(readFileSync(join(out, "findings-report.json"), "utf8")) as { findings: unknown[] };
    expect(raw.find((finding) => finding.id === "DEP-OSV-00")?.evidence).toContain("declarations/package-lock.json");
    expect(raw.find((finding) => finding.id === "DEP-OSV-00")?.evidence).toContain("manifest-only/package.json");
    expect(report.findings).toEqual(raw);
    expect(validateDryRunFamily(out)).toEqual({ ok: true, errors: [] });
  });

  it("retains the manifest-only boundary without inventing a provider invocation", async () => {
    rmSync(join(target, "package-lock.json"));
    rmSync(join(target, "nested/package-lock.json"));
    await generateDryRun(target, out);
    expect(providerPaths).toHaveLength(0);
    const raw = JSON.parse(readFileSync(join(out, "findings.json"), "utf8")) as { id: string; evidence: string }[];
    expect(raw.find((finding) => finding.id === "DEP-OSV-00")?.evidence).toContain("no selected supported lockfile");
    expect(validateDryRunFamily(out)).toEqual({ ok: true, errors: [] });
  });

  it.each(["missing", "invalid", "omitted"] as const)("preserves the previous family when one required nested query is %s despite a successful root query", async (failure) => {
    await generateDryRun(target, out);
    const files = ["findings.json", "pii-data-map.json", "scorecard.json", "findings-report.json", "artifact-family.json"];
    const before = files.map((name) => readFileSync(join(out, name), "utf8"));
    providerFailure = failure;
    await expect(generateDryRun(target, out)).rejects.toThrow(/OSV required live execution/);
    expect(files.map((name) => readFileSync(join(out, name), "utf8"))).toEqual(before);
    expect(validateDryRunFamily(out)).toEqual({ ok: true, errors: [] });
  });
});
