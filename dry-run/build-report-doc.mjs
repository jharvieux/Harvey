// Compatibility entry point: a derived report can no longer be rebuilt independently of its
// raw source/scorecard. The owning dry-run CLI publishes all current artifacts together.
import { spawnSync } from "node:child_process";
import { fileURLToPath, URL } from "node:url";

const report = fileURLToPath(new URL("findings-report.json", import.meta.url));
const validator = fileURLToPath(new URL("../src/cli/validate-findings.ts", import.meta.url));
const result = spawnSync(process.execPath, ["--import", "tsx", validator, report], { stdio: "inherit", cwd: fileURLToPath(new URL("../", import.meta.url)) });
if (result.error) throw result.error;
if (result.status !== 0) {
  console.error("Regenerate the complete family with pnpm exec tsx src/cli/dry-run.ts --target targets/calibration --out dry-run.");
  process.exit(result.status ?? 1);
}
console.log(`Report already belongs to the validated dry-run family: ${report}`);
