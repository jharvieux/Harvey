import { readFileSync } from "node:fs";
import { join } from "node:path";

// BENIGN TWIN (#2130): an operator hook receives the trusted repository root and reads one fixed
// filename. This hidden tooling path is not a remotely callable library entry point.
export function readMemory(root) {
  return readFileSync(join(root, "MEMORY.md"), "utf8");
}
