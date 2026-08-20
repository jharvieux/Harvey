import "./sync-stdio.js";
import { readFileSync } from "node:fs";
import { executeCapacityScan } from "../capacity-runner.js";

const USAGE = "usage: pnpm exec tsx src/cli/capacity-scan.ts --contract <capacity-contract.json>";
const args = process.argv.slice(2);

if (args.includes("--help")) {
  console.log(USAGE);
} else {
  const contractIndex = args.indexOf("--contract");
  const contractPath = contractIndex >= 0 ? args[contractIndex + 1] : undefined;
  const expectedArgs = contractPath === undefined ? [] : ["--contract", contractPath];

  if (contractPath === undefined || args.length !== expectedArgs.length || args.some((arg, index) => arg !== expectedArgs[index])) {
    console.error(USAGE);
    process.exitCode = 2;
  } else {
    try {
      const input = JSON.parse(readFileSync(contractPath, "utf8")) as unknown;
      const receipt = await executeCapacityScan(input);
      console.log(JSON.stringify(receipt, null, 2));
    } catch (error) {
      const detail = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
      console.error(`capacity scan refused: ${detail}`);
      process.exitCode = 2;
    }
  }
}
