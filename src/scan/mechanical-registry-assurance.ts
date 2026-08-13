import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export interface MechanicalEngineEvidence {
  status: "covered" | "structured-exception";
  path?: string;
  detail: string;
}

interface MechanicalProducerAssurance {
  positiveFixture: MechanicalEngineEvidence;
  benignTwin: MechanicalEngineEvidence;
  conservation: MechanicalEngineEvidence;
  corpus: MechanicalEngineEvidence;
  cadence: MechanicalEngineEvidence;
}

const evidenceRoot = fileURLToPath(new URL("../../", import.meta.url));
const exception = (detail: string): MechanicalEngineEvidence => ({ status: "structured-exception", detail });
const covered = (path: string, detail: string): MechanicalEngineEvidence => ({ status: "covered", path, detail });

export function producerAssurance(id: string, implementation: { file: string; exportName: string }, fixture?: string): MechanicalProducerAssurance {
  const verifiedFixture = fixture && existsSync(join(evidenceRoot, fixture)) && readFileSync(join(evidenceRoot, fixture), "utf8").includes(implementation.exportName) ? fixture : undefined;
  const fixtureEvidence = (kind: "positive fixture" | "benign twin"): MechanicalEngineEvidence => verifiedFixture
    ? covered(verifiedFixture, `${id}: ${kind} exercises ${implementation.exportName} through this producer-linked test.`)
    : exception(`${id}: no producer-specific ${kind} exists; no module-level or generic suite is presented as evidence for ${implementation.exportName}.`);
  return {
    positiveFixture: fixtureEvidence("positive fixture"),
    benignTwin: fixtureEvidence("benign twin"),
    conservation: exception(`${id}: no producer-specific conservation plant exists; the M1 module plant conserves output but does not prove this producer can fire.`),
    corpus: covered("src/cli/corpus-drift.ts", `${id}: every selected pinned-corpus target serializes this producer's execution record, including zero-finding and not-applicable populations.`),
    cadence: covered(".github/workflows/corpus-drift.yml", `${id}: the pinned-corpus workflow executes this producer on pull requests and its scheduled cadence.`),
  };
}
