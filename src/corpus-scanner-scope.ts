import { execFileSync } from "node:child_process";
import { readRecursiveSafe } from "./fs-walk.js";

const SOURCE_LIKE = /(?:^|\/)(?:[^/]+\.(?:[cm]?[jt]sx?|json|ya?ml|toml|sql|prisma|py|rb|go|java|rs|php|c|cc|cpp|h|hpp|mdx?)|Dockerfile)$/i;
const GENERATED_OR_DEPENDENCY = /(?:^|\/)(?:node_modules|\.git|\.next|dist|build|coverage)(?:\/|$)/;

/** Count the target-owned units a corpus scanner could examine, never installed dependencies. */
export function countCorpusScannerUnits(targetDir: string): number {
  try {
    const tracked = execFileSync("git", ["-C", targetDir, "ls-files", "-z", "--", "."], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).split("\0").filter(Boolean).length;
    if (tracked > 0) return tracked;
  } catch {
    // Non-git fixtures still get a bounded source-like census below.
  }

  return Math.max(1, readRecursiveSafe(targetDir).filter((path) => SOURCE_LIKE.test(path) && !GENERATED_OR_DEPENDENCY.test(path)).length);
}
