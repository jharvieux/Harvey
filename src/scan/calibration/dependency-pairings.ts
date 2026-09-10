import { readFileSync } from "node:fs";
import { join } from "node:path";
import { assertOsvExecution, type OsvAssessment, type OsvExecutionReceipt } from "../dependencies.js";
import { MechanicalScanContext } from "../mechanical-context.js";
import { observeOsvInputs, runRegisteredDependencyDetectors } from "../mechanical-dependency-registry.js";
import type { ExecutedCorpusPair } from "../rule-corpus-pairing.js";

interface DependencyCorpusPair extends ExecutedCorpusPair {
  positive: ExecutedCorpusPair["positive"] & { assessment: OsvAssessment; execution: OsvExecutionReceipt };
  negative: ExecutedCorpusPair["negative"] & { assessment: OsvAssessment; execution: OsvExecutionReceipt };
}

// These existing roots exercise missing input and complete package examination.
// supported-app holds only root lockfile metadata; test-quality supplies resolved packages.
export async function observeDependencyCorpusPairs(targetDir: string): Promise<DependencyCorpusPair[]> {
  const scanRoot = async (fixture: string) => {
    const scanDir = join(targetDir, fixture);
    const context = new MechanicalScanContext(scanDir);
    try {
      const pkg = JSON.parse(readFileSync(join(scanDir, "package.json"), "utf8")) as {
        dependencies?: Record<string, string>; devDependencies?: Record<string, string>;
      };
      const osv = observeOsvInputs(scanDir, context);
      assertOsvExecution(osv.assessment, osv.execution);
      const input = { scanDir, context, pkg, osv, skipNetworkChecks: true };
      const early = await runRegisteredDependencyDetectors(input, "early");
      const supply = await runRegisteredDependencyDetectors(input, "supply");
      return { fixture, osv, findingsByDetector: { ...early.findingsByDetector, ...supply.findingsByDetector }, records: [...early.records, ...supply.records] };
    } finally { context.dispose(); }
  };
  const positive = await scanRoot("fixtures/legacy-app");
  const negative = await scanRoot("test-quality");
  if (!positive.osv.assessment.inventory.inputs.some((input) => input.path === "package.json" && input.disposition === "missing-input")) {
    throw new Error("The dependency pairing positive no longer has its missing resolved input");
  }
  if (negative.osv.assessment.status !== "assessed" || !negative.osv.assessment.invocations.length ||
      negative.osv.assessment.invocations.some((input) => input.status !== "assessed" || input.examinedPackages.length === 0)) {
    throw new Error("The dependency pairing negative did not complete its selected package examination");
  }
  const cases = [
    { unit: "Known-vulnerable dependency — coverage not assessed", detector: "osv-advisories", positive: "P-DEP-OSV-COVERAGE-NOT-ASSESSED", negative: "N-DEP-OSV-ASSESSMENT-COMPLETE", location: "(repo-wide)" },
    { unit: "Missing lockfile", detector: "lockfile-presence", positive: "P-MISSING-LOCKFILE", negative: "N-LOCKFILE-RESOLVED", location: "test-quality" },
  ];
  return cases.map((testCase) => {
    const positiveReceipt = positive.records.find((record) => record.detector === testCase.detector);
    const negativeReceipt = negative.records.find((record) => record.detector === testCase.detector);
    if (!positiveReceipt || !negativeReceipt) throw new Error(`Missing dependency pairing producer receipt: ${testCase.detector}`);
    return {
      unit: testCase.unit, detector: testCase.detector,
      positive: {
        entry: testCase.positive, fixture: positive.fixture, findings: positive.findingsByDetector[testCase.detector]!, receipt: positiveReceipt,
        assessment: positive.osv.assessment, execution: positive.osv.execution!,
      },
      negative: {
        entry: { id: testCase.negative, kind: "negative", cls: `Completed dependency root: ${testCase.unit}`, location: testCase.location, match: [testCase.unit], note: "Scored only against the independently executed test-quality root, whose selected lockfile resolves a nonempty package population. Absence of this taxonomy requires a completed producer receipt; it is not inferred from another root's aggregate output." },
        fixture: negative.fixture, findings: negative.findingsByDetector[testCase.detector]!, receipt: negativeReceipt,
        assessment: negative.osv.assessment, execution: negative.osv.execution!,
      },
    };
  });
}
