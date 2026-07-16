import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { coveringTests, runStubCheck, stubExportedFunctions, stubSurvivalFindings, type StubTestRunner } from "./stub-check.js";
import type { SourceInput } from "./detectors/common.js";

const calc: SourceInput = {
  path: "src/calc.ts",
  text: `export function add(a: number, b: number): number {
  return a + b;
}

function helper(x: number): number {
  return x * 2;
}

export const double = (x: number): number => helper(x);

export const triple = (x: number): number => {
  return x * 3;
};

export declare function typed(): void;

export const LIMIT = 100;
`,
};

describe("stubExportedFunctions", () => {
  const variants = stubExportedFunctions(calc);

  it("stubs every exported function shape (declaration, concise arrow, block arrow) and nothing else", () => {
    // helper (not exported), typed (no body), LIMIT (not a function) are all skipped.
    expect(variants.map((v) => v.exportName)).toEqual(["add", "double", "triple"]);
  });

  it("replaces ONLY the named export's body, leaving the rest of the file byte-identical", () => {
    const add = variants.find((v) => v.exportName === "add")!;
    expect(add.stubbedText).toContain("export function add(a: number, b: number): number { return undefined; }");
    expect(add.stubbedText).not.toContain("return a + b");
    expect(add.stubbedText).toContain("return x * 2"); // helper untouched
    expect(add.stubbedText).toContain("=> helper(x)"); // double untouched
  });

  it("replaces a concise arrow body with (undefined)", () => {
    const dbl = variants.find((v) => v.exportName === "double")!;
    expect(dbl.stubbedText).toContain("export const double = (x: number): number => (undefined);");
    expect(dbl.stubbedText).toContain("return a + b"); // add untouched
  });
});

describe("coveringTests", () => {
  const files: SourceInput[] = [
    calc,
    { path: "src/calc.test.ts", text: `import { add } from "./calc.js";` },
    { path: "tests/calc-int.spec.ts", text: `import { double } from "../src/calc.js";` },
    { path: "src/other.test.ts", text: `import { other } from "./other.js";` },
  ];

  it("finds the co-located basename test AND an import-resolved test elsewhere, not unrelated tests", () => {
    expect(coveringTests("src/calc.ts", files)).toEqual(["src/calc.test.ts", "tests/calc-int.spec.ts"]);
  });
});

describe("runStubCheck / stubSurvivalFindings", () => {
  const files: SourceInput[] = [calc, { path: "src/calc.test.ts", text: `import { add } from "./calc.js";` }, { path: "src/uncovered.ts", text: "export function lonely(): number {\n  return 1;\n}\n" }];

  it("re-runs the covering suite once per stubbed export and skips files with no covering tests", () => {
    const seen: string[] = [];
    const runner: StubTestRunner = (stub, tests) => {
      seen.push(stub.exportName);
      expect(stub.stubbedText).not.toBe(calc.text); // the runner must receive the STUB, not the original
      expect(tests).toEqual(["src/calc.test.ts"]);
      return stub.exportName === "add";
    };
    const runs = runStubCheck(files, runner);
    expect(seen).toEqual(["add", "double", "triple"]);
    expect(runs.filter((r) => r.file === "src/uncovered.ts")).toHaveLength(0); // NoCoverage territory, not survival
    expect(runs.map((r) => [r.exportName, r.suitePassed])).toEqual([
      ["add", true],
      ["double", false],
      ["triple", false],
    ]);
  });

  it("emits a Confirmed M8-01-* finding per survival, distinct from Stryker/M8-00 output", () => {
    const runs = runStubCheck(files, (stub) => stub.exportName === "add");
    const findings = stubSurvivalFindings(runs);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      id: "M8-01-01",
      taxonomy: "M8 — Survives implementation deletion",
      category: "Test quality",
      severity: "Medium",
      confidence: "Confirmed",
      location: "src/calc.ts:1",
    });
    expect(findings[0]?.evidence).toContain("src/calc.test.ts");
  });
});

// --- executed calibration proof (#373 acceptance) ------------------------------------
// The planted pair (audit-log.ts / audit-log.deletion-surviving.test.ts) is proven to survive
// deletion by actually EXECUTING the covering test against the real and stubbed source —
// transpiled with the repo's own TypeScript and run under a minimal describe/it/expect shim —
// not by asserting the answer from the fixture's comments. discount.tautological.test.ts is
// the executed contrast: weak (Stryker leaves survivors on it) but NOT deletion-surviving,
// because its single assertion does check a return value.

const FIXTURES = fileURLToPath(new URL("../targets/calibration/test-quality/", import.meta.url));

function load(name: string): SourceInput {
  return { path: name, text: readFileSync(`${FIXTURES}${name}`, "utf8") };
}

function execModule(source: string, requireShim: (spec: string) => unknown): Record<string, unknown> {
  const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  const mod = { exports: {} as Record<string, unknown> };
  new Function("require", "module", "exports", js)(requireShim, mod, mod.exports);
  return mod.exports;
}

function runSuite(testSource: string, subjectExports: Record<string, unknown>): { passed: number; failed: number } {
  const counts = { passed: 0, failed: 0 };
  const shim = {
    describe: (_name: string, fn: () => void) => fn(),
    it: (_name: string, fn: () => unknown) => {
      try {
        fn();
        counts.passed++;
      } catch {
        counts.failed++;
      }
    },
    expect: (actual: unknown) => ({
      toBe(expected: unknown) {
        if (actual !== expected) throw new Error(`expected ${String(actual)} to be ${String(expected)}`);
      },
    }),
  };
  execModule(testSource, (spec) => {
    if (spec === "vitest") return shim;
    return subjectExports;
  });
  return counts;
}

describe("M8-P-DELETION-SURVIVING calibration pair (executed, not recorded)", () => {
  const auditLog = load("audit-log.ts");
  const auditLogTest = load("audit-log.deletion-surviving.test.ts");
  const discount = load("discount.ts");
  const discountTest = load("discount.tautological.test.ts");

  it("the planted test passes against the real implementation (it is a live, green test)", () => {
    expect(runSuite(auditLogTest.text, execModule(auditLog.text, () => ({})))).toEqual({ passed: 1, failed: 0 });
  });

  it("the planted test STILL passes with logAuditEvent's body deleted — survival proven by execution", () => {
    const stub = stubExportedFunctions(auditLog).find((v) => v.exportName === "logAuditEvent")!;
    expect(runSuite(auditLogTest.text, execModule(stub.stubbedText, () => ({})))).toEqual({ passed: 1, failed: 0 });
  });

  it("contrast: discount's weak test does NOT survive deletion (weak per Stryker, but assertion-backed)", () => {
    expect(runSuite(discountTest.text, execModule(discount.text, () => ({})))).toEqual({ passed: 1, failed: 0 });
    const stub = stubExportedFunctions(discount).find((v) => v.exportName === "applyDiscount")!;
    expect(runSuite(discountTest.text, execModule(stub.stubbedText, () => ({})))).toEqual({ passed: 0, failed: 1 });
  });

  it("the full pipeline flags exactly logAuditEvent when the runner executes the suites for real", () => {
    const files = [auditLog, auditLogTest, discount, discountTest];
    const bySubject = new Map([
      [auditLog.path, auditLogTest],
      [discount.path, discountTest],
    ]);
    const runner: StubTestRunner = (stub) => {
      const test = bySubject.get(stub.file)!;
      return runSuite(test.text, execModule(stub.stubbedText, () => ({}))).failed === 0;
    };
    const findings = stubSurvivalFindings(runStubCheck(files, runner));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location).toMatch(/^audit-log\.ts:\d+$/);
    expect(findings[0]?.title).toContain("logAuditEvent");
  });
});
