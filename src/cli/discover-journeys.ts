import "./sync-stdio.js";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { discoverJourneyInventoryFromCliTarget } from "../journey-discovery.js";
import { serializeJourneyInventoryV1 } from "../journey-schema.js";
import { arg, assertKnownFlags, targetDir } from "./args.js";

function positionalTarget(argv: string[]): string | undefined {
  for (let index = 2; index < argv.length; index++) {
    const token = argv[index];
    if (token === "--dir" || token === "--target" || token === "--out") { index += 1; continue; }
    if (token && !token.startsWith("--")) return token;
  }
  return undefined;
}

export function main(argv: string[] = process.argv): void {
  assertKnownFlags(["--dir", "--target", "--out"], argv.slice(2));
  const positional = positionalTarget(argv);
  const flagged = arg("--dir", argv) ?? arg("--target", argv);
  if (positional && flagged && resolve(positional) !== resolve(flagged)) throw new Error(`positional target (${positional}) and --dir/--target (${flagged}) disagree`);
  const target = resolve(positional ?? targetDir(argv));
  const serialized = serializeJourneyInventoryV1(discoverJourneyInventoryFromCliTarget(target));
  const output = arg("--out", argv);
  if (!output || output === "-") process.stdout.write(serialized);
  else writeFileSync(resolve(output), serialized, "utf8");
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try { main(); }
  catch (error) {
    console.error(`Journey discovery failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
