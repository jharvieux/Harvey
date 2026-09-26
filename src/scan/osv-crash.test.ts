// #1752 negative controls: runOsvScanner used to treat ANY non-empty stdout as a complete report,
// discarding the exit code and signal — the #1664 swallow shape. Each mock below replays a failure
// shape MEASURED on 2026-07-31 against osv-scanner 2.3.8 (see runOsvScanner's comment in
// dependencies.ts), not an invented one. Same harness shape as semgrep-crash.test.ts.

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";

let osvBehavior: (args: string[]) => string = () => {
  throw new Error("test forgot to set osvBehavior");
};

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    execFileSync: vi.fn((bin: string, args: string[], opts?: unknown) => {
      if (bin === "osv-scanner") return osvBehavior(args);
      return actual.execFileSync(bin as never, args as never, opts as never) as never;
    }),
  };
});

const { assertOsvExecution, inventoryOsvInputs, osvUnavailableFinding, runOsvScanner, validateOsvAssessment } = await import("./dependencies.js");

// runOsvScanner only invokes the binary when a lockfile exists — the mock never reads it.
const dir = mkdtempSync(join(tmpdir(), "harvey-osv-crash-"));
writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/lodash": { version: "4.17.11" } } }));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

// The real report shape (osv-scanner 2.3.8 over targets/calibration emits 230,602 bytes of this).
const COMPLETE_REPORT = JSON.stringify({
  results: [{ source: { path: "package-lock.json" }, packages: [{ package: { name: "lodash", version: "4.17.11", ecosystem: "npm" }, vulnerabilities: [{ id: "GHSA-x", summary: "s" }] }] }],
});

function execError(over: { status?: number | null; signal?: string | null; stdout?: string; code?: string }): Error {
  const err = new Error("Command failed: osv-scanner") as Error & { status: number | null; signal: string | null; stdout: string | undefined; code: string | undefined };
  err.status = over.status ?? null;
  err.signal = over.signal ?? null;
  err.stdout = over.stdout;
  err.code = over.code;
  return err;
}

describe("runOsvScanner refuses an incomplete run (#1752)", () => {
  it("exit 1 with the complete report is the benign vulns-found case — parsed, no failure", () => {
    osvBehavior = () => {
      throw execError({ status: 1, stdout: COMPLETE_REPORT });
    };
    const { result, failure } = runOsvScanner(dir);
    expect(failure).toBeUndefined();
    expect(result.results?.[0]?.packages?.[0]?.vulnerabilities?.[0]?.id).toBe("GHSA-x");
  });

  it("a signal-killed run is a failure naming the signal, even with a truncated report on stdout (MEASURED: SIGKILL mid-flush left 196,563 of 230,602 bytes)", () => {
    osvBehavior = () => {
      throw execError({ signal: "SIGKILL", stdout: COMPLETE_REPORT.slice(0, 120) });
    };
    const { result, failure } = runOsvScanner(dir);
    expect(failure).toContain("killed by signal SIGKILL");
    expect(result).toEqual({ results: [] });
  });

  it("a maxBuffer kill (ENOBUFS + SIGTERM, truncated stdout) is a failure naming the cap, never an uncaught SyntaxError", () => {
    osvBehavior = () => {
      throw execError({ signal: "SIGTERM", code: "ENOBUFS", stdout: COMPLETE_REPORT.slice(0, 120) });
    };
    const { failure } = runOsvScanner(dir);
    expect(failure).toContain("64 MiB stdout cap");
  });

  it("exit 127 with empty stdout (corrupt lockfile / dead network / mid-scan connection loss — all MEASURED) names the exit code", () => {
    osvBehavior = () => {
      throw execError({ status: 127, stdout: "" });
    };
    const { failure } = runOsvScanner(dir);
    expect(failure).toContain("exited with code 127");
  });

  it("a missing binary still reads as not-found, not as an incomplete run", () => {
    osvBehavior = () => {
      throw execError({ code: "ENOENT" });
    };
    const { failure } = runOsvScanner(dir);
    expect(failure).toContain("not found on PATH");
  });

  it("exit 0 with non-JSON stdout degrades to a failure instead of an uncaught SyntaxError", () => {
    osvBehavior = () => "<ERROR: not a report>";
    const { result, failure } = runOsvScanner(dir);
    expect(failure).toContain("something other than its JSON report");
    expect(result).toEqual({ results: [] });
  });

  it("exit 1 with EMPTY stdout is a failure, not a silently clean scan", () => {
    osvBehavior = () => {
      throw execError({ status: 1, stdout: "" });
    };
    const { failure } = runOsvScanner(dir);
    expect(failure).toContain("printed no report");
  });
});


describe("OSV input inventory and effective examination (#2033)", () => {
  const roots: string[] = [];
  afterAll(() => roots.forEach((root) => rmSync(root, { recursive: true, force: true })));
  const root = (): string => { const value = mkdtempSync(join(tmpdir(), "harvey-osv-inputs-")); roots.push(value); return value; };
  const write = (root: string, path: string, text: string): void => { mkdirSync(join(root, path, ".."), { recursive: true }); writeFileSync(join(root, path), text); };
  const lock = (name = "chosen", version = "1.0.0"): string => `lockfileVersion: '9.0'\nimporters:\n  .: {}\npackages:\n  '${name}@${version}':\n    resolution: {integrity: sha512-fixture}\n`;
  const provider = (args: string[]): string => {
    expect(args).toContain("--all-packages");
    const path = args[args.indexOf("--lockfile") + 1]!;
    return JSON.stringify({ results: [{ source: { path }, packages: [{ package: { name: "chosen", version: "1.0.0", ecosystem: "npm" } }] }] });
  };

  it("selects every supported root and binds provider identities to the selected lock rather than SBOM precedence", () => {
    const target = root();
    write(target, "pnpm-lock.yaml", lock());
    write(target, "package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/other": { version: "9.0.0" } } }));
    write(target, "nextjs/pnpm-lock.yaml", lock());
    write(target, "scripts/pr-complexity/pnpm-lock.yaml", lock());
    write(target, "flutter/pubspec.lock", "packages: {}\n");
    write(target, "packages/cli/bun.lock", "{}\n");
    const calls: string[][] = [];
    osvBehavior = (args) => { calls.push(args); return provider(args); };
    const run = runOsvScanner(target);
    expect(run.failure).toBeUndefined();
    expect(calls).toHaveLength(3);
    expect(run.assessment.status).toBe("partial");
    expect(run.assessment.invocations.map((input) => [input.path, input.examinedPackages])).toEqual([
      ["nextjs/pnpm-lock.yaml", ["npm:chosen@1.0.0"]],
      ["pnpm-lock.yaml", ["npm:chosen@1.0.0"]],
      ["scripts/pr-complexity/pnpm-lock.yaml", ["npm:chosen@1.0.0"]],
    ]);
    expect(run.assessment.inventory.inputs.find((input) => input.path === "package-lock.json")).toMatchObject({ disposition: "unselected", selectedBy: "pnpm-lock.yaml" });
    expect(run.assessment.reason).toContain("flutter/pubspec.lock");
    expect(run.assessment.reason).toContain("packages/cli/bun.lock");
    const missingRoot = structuredClone(run.assessment);
    missingRoot.invocations.pop();
    expect(() => validateOsvAssessment(missingRoot, run.result, inventoryOsvInputs(target))).toThrow("does not reconcile");
    const invented = structuredClone(run.assessment);
    invented.invocations[0]!.examinedPackages = ["npm:other@9.0.0"];
    expect(() => validateOsvAssessment(invented, run.result, inventoryOsvInputs(target))).toThrow("does not reconcile");
    write(target, "new/pnpm-lock.yaml", lock());
    expect(() => validateOsvAssessment(run.assessment, run.result, inventoryOsvInputs(target))).toThrow("complete prepared-target population");
  });

  it("records no invocation and zero examination for manifest-only and no-ecosystem targets", () => {
    osvBehavior = () => { throw new Error("unexpected provider invocation"); };
    const target = root();
    expect(runOsvScanner(target).assessment).toMatchObject({ status: "not-applicable", invocations: [] });
    write(target, "package.json", JSON.stringify({ dependencies: { axios: "^1.0.0" } }));
    const run = runOsvScanner(target);
    expect(run.failure).toBeUndefined();
    expect(run.assessment).toMatchObject({ status: "not-assessed", invocations: [] });
    expect(run.assessment.reason).toContain("manifest ranges are not resolved versions");
  });

  it("uses npm package names for aliases and excludes known workspace links from resolved examination", () => {
    const target = root();
    write(target, "package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: {
      "node_modules/alias": { name: "chosen", version: "1.0.0" },
      "node_modules/workspace-member": { link: true, resolved: "packages/member" },
      "packages/member": { name: "workspace-member", version: "0.0.0" },
    } }));
    osvBehavior = (args) => JSON.stringify({ results: [{ source: { path: args.at(-1) }, packages: [
      { package: { name: "chosen", version: "1.0.0", ecosystem: "npm" } },
      { package: { name: "workspace-member", version: "", ecosystem: "npm" } },
    ] }] });
    const run = runOsvScanner(target);
    expect(run.failure).toBeUndefined();
    expect(run.assessment.invocations[0]).toMatchObject({ status: "assessed", examinedPackages: ["npm:chosen@1.0.0"], unassessedPackages: [], unversionedPackages: ["workspace-member"] });
    expect(run.assessment.reason).toContain("first-party workspace package/link");
    expect(run.assessment.reason).not.toContain("npm:alias");
  });

  it.each([false, true])("rejects an extra provider identity, including when expected packages are also returned: %s", (withExpected) => {
    const target = root();
    write(target, "pnpm-lock.yaml", lock());
    osvBehavior = (args) => {
      const raw = JSON.parse(provider(args));
      if (!withExpected) raw.results[0].packages = [];
      raw.results[0].packages.push({ package: { name: "invented", version: "9.9.9", ecosystem: "npm" } });
      return JSON.stringify(raw);
    };
    const invalid = runOsvScanner(target);
    expect(invalid.failure).toContain("package identities absent from selected input: npm:invented@9.9.9");
    expect(invalid.assessment.status).toBe("not-assessed");
    expect(invalid.assessment.invocations[0]!.examinedPackages).toEqual([]);
    osvBehavior = provider;
    const valid = runOsvScanner(target);
    const raw = structuredClone(valid.result);
    raw.results![0]!.packages!.push({ package: { name: "invented", version: "9.9.9", ecosystem: "npm" } });
    const forged = structuredClone(valid.assessment);
    forged.invocations[0]!.examinedPackages.push("npm:invented@9.9.9");
    expect(() => validateOsvAssessment(forged, raw, inventoryOsvInputs(target))).toThrow("package identities absent from selected input");
  });

  it.each(["0.0.0", "1.0.0"])("distinguishes a workspace name from a locked third-party coordinate at local version %s", (localVersion) => {
    const target = root();
    write(target, "package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: {
      "node_modules/chosen": { link: true, resolved: "packages/local" },
      "packages/local": { name: "chosen", version: localVersion },
      "node_modules/transitive/node_modules/chosen": { version: "1.0.0" },
      "node_modules/transitive": { version: "2.0.0" },
    } }));
    osvBehavior = (args) => JSON.stringify({ results: [{ source: { path: args.at(-1) }, packages: [["chosen", ""], ["chosen", localVersion], ["chosen", "1.0.0"], ["transitive", "2.0.0"]].map(([name, version]) => ({ package: { name, version, ecosystem: "npm" } })) }] });
    const run = runOsvScanner(target);
    expect(run.failure).toBeUndefined();
    const input = run.assessment.invocations[0]!;
    expect(input.notApplicablePackages).not.toContain("npm:chosen@1.0.0");
    if (localVersion === "0.0.0") {
      expect(input).toMatchObject({ status: "assessed", examinedPackages: ["npm:chosen@1.0.0", "npm:transitive@2.0.0"], unassessedPackages: [] });
      expect(input.notApplicablePackages).toEqual(["npm:chosen@0.0.0", "npm:chosen@unresolved"]);
    } else {
      expect(input).toMatchObject({ status: "partial", examinedPackages: ["npm:transitive@2.0.0"], unassessedPackages: ["npm:chosen@1.0.0"] });
      expect(input.reason).toContain("provider coordinate does not distinguish their origins");
    }
  });

  it("binds supporting pnpm workspace bytes without treating them as queried packages", () => {
    const target = root();
    write(target, "pnpm-lock.yaml", lock());
    write(target, "pnpm-workspace.yaml", "packages: ['apps/*']\n");
    const calls: string[][] = [];
    osvBehavior = (args) => { calls.push(args); return provider(args); };
    const run = runOsvScanner(target);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.at(-1)).toBe(join(target, "pnpm-lock.yaml"));
    const metadata = run.assessment.inventory.inputs.find((input) => input.path === "pnpm-workspace.yaml")!;
    expect(metadata).toMatchObject({ kind: "manifest", disposition: "covered", selectedBy: "pnpm-lock.yaml" });
    expect(metadata.reason).toContain("not passed to OSV --lockfile and contributes zero resolved examined units");
    write(target, "pnpm-workspace.yaml", "packages: ['packages/*']\n");
    const changed = inventoryOsvInputs(target);
    expect(changed.inputs.filter((input) => input.disposition === "selected")).toEqual(run.assessment.inventory.inputs.filter((input) => input.disposition === "selected"));
    expect(() => validateOsvAssessment(run.assessment, run.result, changed)).toThrow("complete prepared-target population");
  });

  it("hashes unsupported binary lockfiles as bytes without decoding loss", () => {
    const target = root();
    const bytes = Buffer.from([0xff, 0xfe, 0x80, 0x00, 0x01]);
    writeFileSync(join(target, "bun.lockb"), bytes);
    expect(inventoryOsvInputs(target).inputs[0]).toMatchObject({ disposition: "unsupported", sha256: createHash("sha256").update(bytes).digest("hex") });
  });

  it("rejects unresolved lock versions before invoking the provider and non-concrete provider versions before examination", () => {
    const target = root();
    write(target, "package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/chosen": { version: "^1.0.0" } } }));
    osvBehavior = () => { throw new Error("a range is not an invokable resolved version"); };
    const invalidInput = runOsvScanner(target);
    expect(invalidInput.failure).toContain("selected lockfile contains unresolved package versions");
    expect(invalidInput.assessment.inventory.inputs[0]!.resolvedPackages).toEqual([]);
    expect(invalidInput.assessment.invocations[0]!.examinedPackages).toEqual([]);
    write(target, "package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/chosen": { version: "1.0.0" } } }));
    osvBehavior = (args) => provider(args).replace('"version":"1.0.0"', '"version":"^1.0.0"');
    const invalidProvider = runOsvScanner(target);
    expect(invalidProvider.failure).toContain("non-concrete resolved version");
    expect(invalidProvider.assessment.invocations[0]!.examinedPackages).toEqual([]);
  });

  it("conserves provider omissions as explicit unassessed identities while keeping actual examined packages", () => {
    const target = root();
    write(target, "pnpm-lock.yaml", lock() + "  'omitted@2.0.0':\n    resolution: {integrity: sha512-fixture}\n");
    osvBehavior = provider;
    const run = runOsvScanner(target);
    expect(run.failure).toBeUndefined();
    expect(run.assessment.status).toBe("partial");
    expect(run.assessment.invocations[0]).toMatchObject({ status: "partial", examinedPackages: ["npm:chosen@1.0.0"], unassessedPackages: ["npm:omitted@2.0.0"] });
    expect(run.assessment.reason).toContain("npm:omitted@2.0.0");
    expect(osvUnavailableFinding(run.assessment).title).toContain("1 resolved packages absent from provider output");
    const hidden = structuredClone(run.assessment);
    hidden.invocations[0]!.unassessedPackages = [];
    expect(() => validateOsvAssessment(hidden, run.result, inventoryOsvInputs(target))).toThrow("does not reconcile");
  });

  it("examines a pnpm alias selected with its actual registry name and peer suffix", () => {
    const target = root();
    const original = "lockfileVersion: '9.0'\nimporters:\n  apps/web:\n    devDependencies:\n      emulate:\n        specifier: npm:@inbox-zero/emulate@0.5.0\n        version: '@inbox-zero/emulate@0.5.0(hono@4.12.18)'\npackages:\n  '@inbox-zero/emulate@0.5.0':\n    resolution: {integrity: sha512-alias}\n";
    write(target, "pnpm-lock.yaml", original);
    let invoked = 0;
    osvBehavior = (args) => {
      invoked++;
      expect(args).toContain("--all-packages");
      expect(readFileSync(args.at(-1)!, "utf8")).toBe(original);
      return JSON.stringify({ results: [{ source: { path: args.at(-1) }, packages: [{ package: { name: "@inbox-zero/emulate", version: "0.5.0", ecosystem: "npm" } }] }] });
    };
    const run = runOsvScanner(target);
    expect(invoked).toBe(1);
    expect(run.failure).toBeUndefined();
    expect(run.assessment).toMatchObject({ status: "assessed", invocations: [{ examinedPackages: ["npm:@inbox-zero/emulate@0.5.0"], unassessedPackages: [] }] });
    expect(run.execution.inputs).toMatchObject([{ status: "completed" }]);
    expect(() => assertOsvExecution(run.assessment, run.execution)).not.toThrow();
    expect(readFileSync(join(target, "pnpm-lock.yaml"), "utf8")).toBe(original);
  });

  it("normalizes pnpm v6 scoped-peer keys for the pinned provider without changing identities, dev/optional flags, or the client lock", () => {
    const target = root();
    const original = [
      "lockfileVersion: '6.0'",
      "packages:",
      "  /@scope/scoped@1.0.0(@types/react@18.3.3):",
      "    resolution: {integrity: sha512-scoped}",
      "    dev: true",
      "  /plain@2.0.0(@types/react@18.3.3):",
      "    resolution: {integrity: sha512-plain}",
      "    optional: true",
      "  /unscoped-peer@3.0.0(react@18.3.1):",
      "    resolution: {integrity: sha512-unscoped-peer}",
      "  /clean@4.0.0:",
      "    resolution: {integrity: sha512-clean}",
      "",
    ].join("\n");
    write(target, "pnpm-lock.yaml", original);
    const originalDigest = createHash("sha256").update(original).digest("hex");
    osvBehavior = (args) => {
      const providerPath = args.at(-1)!;
      expect(providerPath).not.toBe(join(target, "pnpm-lock.yaml"));
      const prepared = readFileSync(providerPath, "utf8");
      expect(prepared).toContain('    name: "@scope/scoped"\n    version: "1.0.0"');
      expect(prepared).toContain('    name: "plain"\n    version: "2.0.0"');
      expect(prepared).not.toContain('    name: "unscoped-peer"');
      expect(prepared).toContain("    dev: true");
      expect(prepared).toContain("    optional: true");
      return JSON.stringify({ results: [{ source: { path: providerPath }, packages: [
        ["@scope/scoped", "1.0.0"], ["plain", "2.0.0"], ["unscoped-peer", "3.0.0"], ["clean", "4.0.0"],
      ].map(([name, version]) => ({ package: { name, version, ecosystem: "npm" } })) }] });
    };
    const run = runOsvScanner(target);
    expect(run.failure).toBeUndefined();
    expect(run.assessment).toMatchObject({ status: "assessed", invocations: [{
      status: "assessed",
      examinedPackages: ["npm:@scope/scoped@1.0.0", "npm:clean@4.0.0", "npm:plain@2.0.0", "npm:unscoped-peer@3.0.0"],
      unassessedPackages: [],
    }] });
    expect(run.assessment.inventory.inputs.find((input) => input.path === "pnpm-lock.yaml")?.providerNormalization).toMatchObject({
      kind: "pnpm-v6-scoped-peer-metadata", normalizedEntries: 2,
    });
    expect(run.assessment.provenance).toContain("2 scoped-peer entries");
    expect(createHash("sha256").update(readFileSync(join(target, "pnpm-lock.yaml"))).digest("hex")).toBe(originalDigest);
  });

  it("keeps normalized pnpm v6 packages partial when the provider still omits one", () => {
    const target = root();
    write(target, "pnpm-lock.yaml", "lockfileVersion: '6.0'\npackages:\n  /plain@2.0.0(@types/react@18.3.3):\n    resolution: {integrity: sha512-plain}\n  /clean@4.0.0:\n    resolution: {integrity: sha512-clean}\n");
    osvBehavior = (args) => JSON.stringify({ results: [{ source: { path: args.at(-1) }, packages: [
      { package: { name: "clean", version: "4.0.0", ecosystem: "npm" } },
    ] }] });
    const run = runOsvScanner(target);
    expect(run.failure).toBeUndefined();
    expect(run.assessment.invocations[0]).toMatchObject({
      status: "partial", examinedPackages: ["npm:clean@4.0.0"], unassessedPackages: ["npm:plain@2.0.0"],
    });
    expect(osvUnavailableFinding(run.assessment).evidence).toContain("npm:plain@2.0.0");
  });

  it("keeps a successful sibling when a selected root fails", () => {
    const target = root();
    write(target, "pnpm-lock.yaml", lock());
    write(target, "nested/pnpm-lock.yaml", lock());
    osvBehavior = (args) => { if (args.at(-1)!.includes("/nested/")) throw execError({ status: 127 }); return provider(args); };
    const run = runOsvScanner(target);
    expect(run.failure).toContain("nested/pnpm-lock.yaml");
    expect(run.assessment.status).toBe("partial");
    expect(run.assessment.invocations.find((input) => input.path === "nested/pnpm-lock.yaml")).toMatchObject({ status: "not-assessed", examinedPackages: [] });
    expect(run.assessment.invocations.find((input) => input.path === "pnpm-lock.yaml")).toMatchObject({ status: "assessed", examinedPackages: ["npm:chosen@1.0.0"] });
    expect(osvUnavailableFinding(run.assessment).title).toContain("exited with code 127");
  });

  it.each(["", "{}", "null", '[]', '{"results":{}}', '{"results":[{}]}', '{"results":[]}'])("rejects incomplete provider output %s", (output) => {
    osvBehavior = () => output;
    const run = runOsvScanner(dir);
    expect(run.failure).toBeTruthy();
    expect(run.assessment.status).toBe("not-assessed");
    expect(run.assessment.invocations[0]?.examinedPackages).toEqual([]);
  });

  it("discloses malformed selected input without inventing resolved units", () => {
    const target = root();
    write(target, "pnpm-lock.yaml", "not a lockfile");
    osvBehavior = () => { throw new Error("malformed input should not be submitted"); };
    const run = runOsvScanner(target);
    expect(run.failure).toContain("input completeness is not established");
    expect(run.assessment.status).toBe("not-assessed");
  });
});


describe("required live OSV execution receipts", () => {
  it("accepts a reconciled live receipt and refuses absent, incomplete, duplicate, foreign, or relabelled execution", () => {
    osvBehavior = () => COMPLETE_REPORT;
    const { assessment, execution } = runOsvScanner(dir);
    expect(() => assertOsvExecution(assessment, execution)).not.toThrow();
    expect(() => assertOsvExecution(assessment)).toThrow(/missing/);
    expect(() => assertOsvExecution(assessment, { ...execution, inputs: [] })).toThrow(/every selected/);
    expect(() => assertOsvExecution(assessment, { ...execution, inputs: [...execution.inputs, ...execution.inputs] })).toThrow(/every selected/);
    expect(() => assertOsvExecution(assessment, { ...execution, inventorySha256: "foreign" })).toThrow(/another input/);
    expect(() => assertOsvExecution(assessment, { ...execution, inputs: [{ ...execution.inputs[0]!, path: "other/package-lock.json" }] })).toThrow(/missing or duplicate/);
    expect(() => assertOsvExecution(assessment, { ...execution, inputs: [{ ...execution.inputs[0]!, sha256: "foreign" }] })).toThrow(/missing or duplicate/);
    expect(() => assertOsvExecution(assessment, { ...execution, inputs: [{ ...execution.inputs[0]!, status: "input-not-assessed", reason: "fabricated static gap" }] })).toThrow(/preflight condition/);
  });
});
