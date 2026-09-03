// #1715 — the light suite has ONE timeout, in vitest.config.ts, with its measurement beside it.
//
// The failure this exists to stop is not a slow test; it is the drift back to per-file literals.
// Four files picked one up incident-by-incident (#1646) while src/fs-walk.test.ts sat in the same
// class with nothing, and each literal carried its own private justification, so nobody could see
// that the DEFAULT was the thing that had never been measured against this suite.
//
// Discovery-backed, not a one-time sweep: the population is recomputed from the tree every run, so
// a new literal fails here instead of quietly becoming the fifth. Same posture as sync-stdio.ts's
// exiting-CLI ratchet and the #1330 conditional-scan registry.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { HEAVY_CLI_TESTS } from "./heavy-cli-tests.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// Vitest accepts both a trailing positional timeout (`it(name, fn, 30_000)`) and an options object
// (`it(name, { timeout: 30_000 }, fn)`). A text pattern for the former missed the latter and let 12
// redundant central-value overrides accumulate. Parse each discovered test file instead: Vitest
// import identity excludes child-process/VM options and includes aliased APIs plus vi.setConfig;
// direct numeric literals keep the ratchet scoped to ad-hoc constants.
const VITEST_TIMEOUT_CALLS = new Set(["it", "test", "describe", "beforeAll", "beforeEach", "afterAll", "afterEach"]);
const VITEST_CONFIG_TIMEOUTS = new Set(["testTimeout", "hookTimeout"]);

function expressionPath(expression: ts.Expression): string[] | undefined {
  if (ts.isIdentifier(expression)) return [expression.text];
  if (ts.isCallExpression(expression)) return expressionPath(expression.expression);
  if (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isNonNullExpression(expression)) return expressionPath(expression.expression);
  if (ts.isPropertyAccessExpression(expression)) {
    const parent = expressionPath(expression.expression);
    return parent ? [...parent, expression.name.text] : undefined;
  }
  if (ts.isElementAccessExpression(expression) && expression.argumentExpression && ts.isStringLiteralLike(expression.argumentExpression)) {
    const parent = expressionPath(expression.expression);
    return parent ? [...parent, expression.argumentExpression.text] : undefined;
  }
  return undefined;
}

function propertyName(name: ts.PropertyName): string | undefined {
  return ts.isIdentifier(name) || ts.isStringLiteralLike(name) ? name.text : undefined;
}

function timeoutLiteralsIn(source: string): string[] {
  const file = ts.createSourceFile("candidate.test.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const calls = new Set<string>();
  const configApis = new Set<string>();
  const namespaces = new Set<string>();
  for (const statement of file.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) || statement.moduleSpecifier.text !== "vitest") continue;
    const bindings = statement.importClause?.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) {
      namespaces.add(bindings.name.text);
      continue;
    }
    if (!bindings || !ts.isNamedImports(bindings)) continue;
    for (const element of bindings.elements) {
      const imported = element.propertyName?.text ?? element.name.text;
      if (VITEST_TIMEOUT_CALLS.has(imported)) calls.add(element.name.text);
      if (imported === "vi") configApis.add(element.name.text);
    }
  }

  const literals: string[] = [];
  const addNumeric = (node: ts.Expression): void => {
    if (ts.isNumericLiteral(node)) literals.push(node.getText(file));
  };
  const addObjectProperties = (node: ts.Expression, names: ReadonlySet<string>): void => {
    if (!ts.isObjectLiteralExpression(node)) return;
    for (const member of node.properties) {
      if (ts.isPropertyAssignment(member) && names.has(propertyName(member.name) ?? "")) addNumeric(member.initializer);
    }
  };
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const path = expressionPath(node.expression);
      const importedCall = path && (calls.has(path[0] ?? "") || (namespaces.has(path[0] ?? "") && VITEST_TIMEOUT_CALLS.has(path[1] ?? "")));
      if (importedCall) {
        for (const argument of node.arguments) {
          addNumeric(argument);
          addObjectProperties(argument, new Set(["timeout"]));
        }
      }
      const setConfig = path && ((configApis.has(path[0] ?? "") && path[1] === "setConfig") || (namespaces.has(path[0] ?? "") && path[1] === "vi" && path[2] === "setConfig"));
      if (setConfig) for (const argument of node.arguments) addObjectProperties(argument, VITEST_CONFIG_TIMEOUTS);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return literals;
}

/**
 * Light-suite files that still carry their own literal, each with the reason the uniform budget
 * does not serve it. This list may only SHRINK: a file that is here and no longer has a literal
 * fails as a stale claim, exactly like TWIN_BACKLOG and the test-only-exports baseline.
 *
 * Heavy files (src/heavy-cli-tests.ts) are not eligible at all — they are excluded from the light
 * suite, their blocking windows ARE the subject of #1120, and their per-test literals are load-
 * bearing rather than incidental.
 */
const AD_HOC_TIMEOUT_BACKLOG: Record<string, string> = {
  "src/cli/fix-execute.test.ts":
    "60-120s per test: each one builds a corpus and spawns the CLIENT's own suites concurrently, so its wall time tracks a spawned toolchain, not this repo's. Measured 20.5s for the whole file on an idle machine.",
  "src/cli/sync-stdio.test.ts":
    "60s: spawns real children and asserts on reader backpressure, so its clock is the child's, and #1768 records that a timing-anchored assertion here is exactly what went flaky.",
  "src/cli/validate-conservation.test.ts":
    "240s: the HARVEY_CONSERVATION_E2E opt-in (#1105) runs the whole ten-module orchestrator in a child. It is skipped in the light suite and runs in conservation.yml.",
  "src/cli/validate-reasons.test.ts":
    "120s on a beforeAll that builds a git fixture and rebuilds the claim baseline through the real CLI. This file already has the highest non-test time in the suite (10512ms measured under contention).",
  "src/cli/validate-secbench.test.ts":
    "120s: runs real semgrep over the SecBench corpus in a child process.",
  "src/fix/verify.test.ts":
    "20s, TIGHTER than the uniform budget on purpose: these assertions prove a client command that hangs is killed at 300ms, so a generous ceiling would let a broken kill path look like a slow machine.",
};

function lightSuiteTestFiles(): string[] {
  const heavy = new Set<string>(HEAVY_CLI_TESTS);
  return execFileSync("git", ["ls-files", "*.test.ts"], { cwd: REPO_ROOT, encoding: "utf8" })
    .trim()
    .split("\n")
    .filter((f) => f.length > 0 && !heavy.has(f));
}

describe("the light suite has one measured timeout, not a literal per incident (#1715)", () => {
  it("no light-suite file carries an unlisted per-test or per-hook timeout literal", () => {
    const files = lightSuiteTestFiles();
    // A discovery that returns nothing would make every assertion below pass vacuously — the shape
    // #1388/#1509 exist to prevent. The population is part of the measurement.
    expect(files.length, "git ls-files found no light-suite test files — the discovery is broken, not the tree").toBeGreaterThan(100);

    const unlisted = files.filter((f) => timeoutLiteralsIn(readFileSync(join(REPO_ROOT, f), "utf8")).length > 0 && !(f in AD_HOC_TIMEOUT_BACKLOG));
    expect(
      unlisted,
      "these light-suite files declare their own test/hook timeout. #1715 settled this once: vitest.config.ts carries one measured 30s budget for the whole light suite. Delete the literal, or add the file to AD_HOC_TIMEOUT_BACKLOG with the reason the uniform budget does not serve it.",
    ).toEqual([]);
  });

  it("no backlog row has outlived its literal", () => {
    const stale = Object.keys(AD_HOC_TIMEOUT_BACKLOG).filter((f) => timeoutLiteralsIn(readFileSync(join(REPO_ROOT, f), "utf8")).length === 0);
    expect(stale, "these files no longer carry a timeout literal, so their backlog rows are claims that are no longer true. Delete the rows — a backlog that never shrinks is a list, not a ratchet.").toEqual([]);
  });

  it("vitest.config.ts sets ONE budget, and testTimeout and hookTimeout agree", () => {
    const config = readFileSync(join(REPO_ROOT, "vitest.config.ts"), "utf8");
    const declared = /const TIMEOUT_MS = ([\d_]+);/.exec(config)?.[1];
    expect(declared, "vitest.config.ts no longer declares a single TIMEOUT_MS — #1715's whole point is that the number lives in exactly one place, with its measurement beside it").toBeDefined();
    expect(declared, "#1715's measured central timeout changed — remeasure the light suite before changing its 30s test/hook budget").toBe("30_000");
    expect(config).toContain("testTimeout: TIMEOUT_MS");
    expect(config).toContain("hookTimeout: TIMEOUT_MS");
    // Inside #1120's standing ceiling: no single blocking window may approach vitest's hardcoded
    // 60s worker->main RPC ack, and a timeout is the ceiling on exactly such a window.
    expect(Number((declared ?? "0").replaceAll("_", ""))).toBeLessThan(60_000);
  });

  it("NEGATIVE CONTROL: the AST detector covers positional and object timeout literals without matching unrelated options", () => {
    expect(timeoutLiteralsIn("import { it } from 'vitest';\nit('x', async () => {\n  await go();\n}, 30_000);\n")).toEqual(["30_000"]);
    expect(timeoutLiteralsIn("import { test as spec } from 'vitest';\nspec('x', { timeout: 30_000 }, async () => {\n  await go();\n});\n")).toEqual(["30_000"]);
    expect(timeoutLiteralsIn("import * as Vitest from 'vitest';\nVitest.describe('x', { timeout: 30_000 }, () => {});\n")).toEqual(["30_000"]);
    expect(timeoutLiteralsIn("import { vi as runtime } from 'vitest';\nruntime.setConfig({ testTimeout: 30_000, hookTimeout: 60_000 });\n")).toEqual(["30_000", "60_000"]);
    expect(timeoutLiteralsIn("import { describe } from 'vitest';\ndescribe('x', { retry: 2, concurrent: true }, () => {});\n")).toEqual([]);
    expect(timeoutLiteralsIn("import { it } from './fixture.js';\nit('x', () => {}, 30_000);\n")).toEqual([]);
    expect(timeoutLiteralsIn("execFileSync('sh', ['-c', c], { timeout: 60_000 });\n")).toEqual([]);
    expect(timeoutLiteralsIn("runInNewContext(source, context, { timeout: 1_000 });\n")).toEqual([]);
  });
});
