import "./sync-stdio.js";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  buildCorpusInputOwnership,
  classifyCorpusDriftRelevance,
  type CorpusInputOwnership,
  type CorpusRegisteredInputOwnership,
  type MechanicalCorpusOwnershipDiscovery,
} from "../corpus-drift-relevance.js";

type Mode = "ownership" | "classify";

const rawArgs = process.argv.slice(2);
const requestedMode = rawArgs[0];
if (requestedMode !== "ownership" && requestedMode !== "classify") {
  console.error("usage: pnpm exec tsx src/cli/corpus-drift-relevance.ts <ownership|classify> ...");
  process.exit(2);
}
const mode: Mode = requestedMode;
const args = rawArgs.slice(1);
const VALUE_FLAGS: Readonly<Record<Mode, ReadonlySet<string>>> = {
  ownership: new Set(["--out", "--mechanical-ownership", "--non-import-inputs"]),
  classify: new Set(["--root", "--base", "--head", "--ownership", "--out"]),
};

function value(flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

for (let index = 0; index < args.length; index += 1) {
  const argument = args[index]!;
  if (!VALUE_FLAGS[mode].has(argument)) {
    console.error(`unknown corpus-drift-relevance ${mode} argument ${JSON.stringify(argument)}`);
    process.exit(2);
  }
  if (!args[index + 1] || args[index + 1]!.startsWith("--")) {
    console.error(`${argument} requires a value`);
    process.exit(2);
  }
  index += 1;
}

function readJson<T>(path: string, label: string): T {
  try {
    return JSON.parse(readFileSync(resolve(path), "utf8")) as T;
  } catch (error) {
    throw new Error(`${label} is unreadable: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function emit(valueToWrite: unknown, outputPath: string | undefined): void {
  const serialized = `${JSON.stringify(valueToWrite, null, 2)}\n`;
  if (outputPath) writeFileSync(resolve(outputPath), serialized);
  else process.stdout.write(serialized);
}

async function liveMechanicalOwnership(): Promise<MechanicalCorpusOwnershipDiscovery> {
  const mechanical = await import("../scan/mechanical.js") as unknown as Record<string, unknown>;
  const discover = mechanical.discoverMechanicalCorpusOwnership;
  if (typeof discover !== "function") {
    throw new Error("src/scan/mechanical.ts does not export discoverMechanicalCorpusOwnership(); C3 is not integrated");
  }
  return await (discover as () => MechanicalCorpusOwnershipDiscovery | Promise<MechanicalCorpusOwnershipDiscovery>)();
}

async function generateOwnership(): Promise<void> {
  const outputPath = value("--out");
  if (!outputPath) throw new Error("ownership mode requires --out <canonical-input-ownership.json>");
  const mechanicalPath = value("--mechanical-ownership");
  const mechanicalOwnership = mechanicalPath
    ? readJson<MechanicalCorpusOwnershipDiscovery>(mechanicalPath, "mechanical corpus ownership receipt")
    : await liveMechanicalOwnership();
  const nonImportPath = value("--non-import-inputs");
  const nonImportBundle = nonImportPath
    ? readJson<{ schema: 1; inputs: readonly CorpusRegisteredInputOwnership[] }>(nonImportPath, "registered non-import ownership receipt")
    : { schema: 1 as const, inputs: [] };
  if (nonImportBundle.schema !== 1 || !Array.isArray(nonImportBundle.inputs)) {
    throw new Error("registered non-import ownership receipt must have schema 1 and an inputs array");
  }
  const { EXTERNAL_CORPUS } = await import("../scan/external-corpus.js");
  const ownership = buildCorpusInputOwnership({
    pinnedTargets: EXTERNAL_CORPUS.map((target) => target.slug),
    mechanicalOwnership,
    nonImportInputs: nonImportBundle.inputs,
  });
  emit(ownership, outputPath);
  console.error(`CORPUS OWNERSHIP: wrote schema 1 with ${ownership.consumers.length} runtime roots, ${ownership.producers.length} live mechanical producer row(s), ${ownership.nonImportInputs.length} registered non-import input(s), and ${ownership.consumers[0]?.targetSelection.targets.length ?? 0} pinned target(s)`);
}

function classify(): void {
  const base = value("--base");
  const ownershipPath = value("--ownership");
  if (!base || !ownershipPath) {
    throw new Error("classify mode requires --base <commit> and --ownership <canonical-input-ownership.json>");
  }
  const ownership = readJson<CorpusInputOwnership>(ownershipPath, "corpus-drift relevance ownership input");
  const receipt = classifyCorpusDriftRelevance({
    repoRoot: resolve(value("--root") ?? process.cwd()),
    base,
    head: value("--head") ?? "HEAD",
    ownership,
  });
  emit(receipt, value("--out"));
  if (receipt.decision === "declared-no-op") {
    console.error(`CORPUS RELEVANCE: declared-no-op — nothing assessed; ${receipt.changed.length} exact Git change(s) are disjoint from closure ${receipt.closureDigest}`);
  } else {
    console.error(`CORPUS RELEVANCE: full-scan — ${receipt.reasons.map((reason) => reason.code).join(", ") || "relevance proof unavailable"}; hosted full-pinned-corpus gate remains the backstop`);
  }
}

async function main(): Promise<void> {
  if (mode === "ownership") await generateOwnership();
  else classify();
}

main().catch((error: unknown) => {
  console.error(`corpus-drift-relevance ${mode} failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(2);
});
