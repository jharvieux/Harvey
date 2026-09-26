// M8 stub-check (#373) — the cheap "would this test survive the implementation being deleted?"
// pre-Stryker instrument. Whole-function deletion is a single-mutant special case of mutation
// testing: O(exported functions) suite runs instead of O(all mutants), so it works as a fast
// triage pass (or fallback) where full Stryker setup isn't available. It only proves the WORST
// case — the suite passes with the body gone entirely; partial mutant survival stays Stryker's
// ground truth (#319).
//
// Pure transforms live here (stub generation, covering-test resolution, verdict → Finding);
// the test-runner side effect is injected (StubTestRunner) so the logic is testable without a
// child process — src/cli/mutation-scan.ts --stub-check wires the real one (write stub, run
// the target's test command, restore).

import { posix } from "node:path";
import ts from "typescript";
import type { Finding } from "./findings.js";
import { parse, type SourceInput } from "./detectors/common.js";
import { isTestFile, resolveModule } from "./detectors/test-intent.js";
import { assertCommandExecutionReceipt, type CommandExecutionReceipt } from "./producer-execution-receipt.js";

const PARSEABLE = /\.([cm]?[jt]s|[jt]sx)$/;

function stripExt(p: string): string {
  return p.replace(/\.([cm]?[jt]s|[jt]sx)$/, "");
}

function lineOf(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

// Not exported (mirrors mutation-scan.ts's convention): callers get these shapes as the
// fully-typed inferred returns of stubExportedFunctions/runStubCheck.
interface StubVariant {
  exportName: string;
  line: number;
  // The whole file with ONLY this export's body replaced by `return undefined` — the
  // "implementation deleted" variant the covering suite is re-run against.
  stubbedText: string;
}

export function stubExportedFunctions(file: SourceInput): StubVariant[] {
  const sf = parse(file.path, file.text);
  const out: StubVariant[] = [];
  const splice = (start: number, end: number, replacement: string) => file.text.slice(0, start) + replacement + file.text.slice(end);
  for (const stmt of sf.statements) {
    const exported = ts.canHaveModifiers(stmt) && ts.getModifiers(stmt)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    if (!exported) continue;
    if (ts.isFunctionDeclaration(stmt) && stmt.name && stmt.body) {
      out.push({ exportName: stmt.name.text, line: lineOf(sf, stmt), stubbedText: splice(stmt.body.getStart(sf), stmt.body.end, "{ return undefined; }") });
    } else if (ts.isVariableStatement(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        if (!ts.isIdentifier(decl.name) || !decl.initializer) continue;
        const init = decl.initializer;
        if (!ts.isArrowFunction(init) && !ts.isFunctionExpression(init)) continue;
        const replacement = ts.isBlock(init.body) ? "{ return undefined; }" : "(undefined)";
        out.push({ exportName: decl.name.text, line: lineOf(sf, decl), stubbedText: splice(init.body.getStart(sf), init.body.end, replacement) });
      }
    }
  }
  return out;
}

// Which test files cover a subject: co-located `foo.test.ts` next to `foo.ts`, plus any test
// file whose imports resolve to the subject — the coarse equivalent of Stryker's `coveredBy`
// when per-test coverage isn't wired.
export function coveringTests(subjectPath: string, files: SourceInput[]): string[] {
  const byPath: ReadonlyMap<string, SourceInput> = new Map(files.filter((f) => PARSEABLE.test(f.path)).map((f) => [f.path, f]));
  const subjectBase = stripExt(posix.basename(subjectPath));
  const out: string[] = [];
  for (const f of files) {
    if (!isTestFile(f.path) || !PARSEABLE.test(f.path)) continue;
    const testBase = stripExt(posix.basename(f.path)).replace(/\.(test|spec)$/, "");
    if (posix.dirname(f.path) === posix.dirname(subjectPath) && testBase === subjectBase) {
      out.push(f.path);
      continue;
    }
    const sf = parse(f.path, f.text);
    const specifiers = sf.statements
      .filter(ts.isImportDeclaration)
      .map((s) => s.moduleSpecifier)
      .filter(ts.isStringLiteralLike)
      .map((s) => s.text);
    if (specifiers.some((spec) => resolveModule(f.path, spec, byPath)?.path === subjectPath)) out.push(f.path);
  }
  return out;
}

interface StubCheckRun {
  file: string;
  exportName: string;
  line: number;
  coveringTests: string[];
  // true = the covering suite still passed with the body deleted; false = a completed non-zero
  // test exit caught the deletion. Interrupted children have no suite verdict.
  suitePassed?: boolean;
  classification: StubCheckClassification;
  executionReceipt: CommandExecutionReceipt;
}

export type StubTestRunner = (stub: { file: string; exportName: string; stubbedText: string }, coveringTests: string[]) => CommandExecutionReceipt;

type StubCheckClassification =
  | { status: "completed"; suitePassed: boolean }
  | { status: "interrupted"; reason: string };

/** A completed non-zero test exit proves the deletion was noticed; interruption proves nothing. */
export function classifyStubCheckReceipt(receipt: CommandExecutionReceipt): StubCheckClassification {
  try {
    assertCommandExecutionReceipt(receipt);
  } catch (error) {
    return { status: "interrupted", reason: `invalid command receipt: ${(error as Error).message}` };
  }
  const { outcome } = receipt;
  if (outcome.state === "exited") return { status: "completed", suitePassed: outcome.exitCode === 0 };
  const detail = [
    `state ${outcome.state}`,
    `exit ${outcome.exitCode ?? "null"}`,
    ...(outcome.observedExitCode === undefined ? [] : [`observed exit ${outcome.observedExitCode}`]),
    `signal ${outcome.signal ?? "null"}`,
    ...(outcome.errorCode ? [`error ${outcome.errorCode}`] : []),
  ].join(", ");
  return { status: "interrupted", reason: `stubbed test command did not complete (${detail})` };
}

export function interruptedStubCheckModuleRecord(runs: readonly StubCheckRun[]): { status: "partial"; note: string } | undefined {
  const interrupted = runs.filter((run) => run.classification.status === "interrupted");
  if (interrupted.length === 0) return undefined;
  const details = interrupted.map((run) => `${run.file}:${run.line} \`${run.exportName}\`: ${run.classification.status === "interrupted" ? run.classification.reason : ""}`).join("; ");
  return {
    status: "partial",
    note: `M8 stub-check is partial: ${interrupted.length} of ${runs.length} stubbed test command(s) was interrupted and cannot prove deletion coverage. ${details}. Completed non-zero test exits remain distinct and count as caught deletions. [MEASURED from retained native command receipts; falsifier: rerun pnpm mutation-scan <target> --stub-check --out /tmp/m8-stub.json, then run node -e 'const a=require(process.argv[1]);process.exit(a.baseline?.classification?.status==="completed"&&a.baseline.classification.suitePassed===true&&Array.isArray(a.runs)&&a.runs.length>0&&a.runs.every(r=>r.classification?.status==="completed")?0:1)' /tmp/m8-stub.json].`,
  };
}

export function interruptedStubBaselineModuleRecord(testCmd: string, classification: Extract<StubCheckClassification, { status: "interrupted" }>): { status: "partial"; note: string } {
  return {
    status: "partial",
    note: `M8 stub-check did not run: the target suite's UNMUTATED baseline was interrupted under \`${testCmd}\` (${classification.reason}). No deletion-survival result is reported. [MEASURED from the retained native command receipt; falsifier: rerun pnpm mutation-scan <target> --stub-check --out /tmp/m8-stub.json, then run node -e 'const a=require(process.argv[1]);process.exit(a.baseline?.classification?.status==="completed"?0:1)' /tmp/m8-stub.json].`,
  };
}

// Every covered exported function is stubbed and re-run — a file with NO covering tests is
// skipped, not failed: "nothing covers this" is the mutation scan's NoCoverage / #224 signal,
// while this instrument's question is "the covering tests exist; do they notice deletion?".
// All runs are returned (not just survivals) so the caller can account for what was checked.
export function runStubCheck(files: SourceInput[], runTests: StubTestRunner): StubCheckRun[] {
  const runs: StubCheckRun[] = [];
  for (const file of files) {
    if (!PARSEABLE.test(file.path) || isTestFile(file.path)) continue;
    const tests = coveringTests(file.path, files);
    if (tests.length === 0) continue;
    for (const v of stubExportedFunctions(file)) {
      const executionReceipt = runTests({ file: file.path, exportName: v.exportName, stubbedText: v.stubbedText }, tests);
      const classification = classifyStubCheckReceipt(executionReceipt);
      runs.push({
        file: file.path,
        exportName: v.exportName,
        line: v.line,
        coveringTests: tests,
        ...(classification.status === "completed" ? { suitePassed: classification.suitePassed } : {}),
        classification,
        executionReceipt,
      });
    }
  }
  return runs;
}

// Distinct taxonomy/id family from a genuine Stryker survived-mutant (M8-00 is #224's
// no-suite finding): M8-01-* marks a dynamically PROVEN deletion survival.
export function stubSurvivalFindings(runs: StubCheckRun[]): Finding[] {
  let n = 0;
  return runs
    .filter((r) => r.classification.status === "completed" && r.suitePassed === true)
    .map((r) => ({
      id: `M8-01-${String(++n).padStart(2, "0")}`,
      status: "Open",
      category: "Test quality",
      title: `Covering tests pass with \`${r.exportName}\` deleted`,
      severity: "Medium" as const,
      confidence: "Confirmed" as const,
      taxonomy: "M8 — Survives implementation deletion",
      location: `${r.file}:${r.line}`,
      evidence: `With \`${r.exportName}\`'s body replaced by \`return undefined\`, its covering test file(s) — ${r.coveringTests.join(", ")} — still passed. Executed, not inferred.`,
      impact: "The most extreme form of false test confidence: the function's entire behavior can vanish and the suite stays green, so no regression in it will ever be caught.",
      fix: "Assert on the function's observable output/effects in the covering tests; confirm the fix by re-running the stub check (and Stryker, where configured).",
      value: 4,
      ease: 3,
      safety: 5,
    }));
}
