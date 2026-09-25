import { readFileSync } from "node:fs";
import { join } from "node:path";
// An exported root has unknown caller provenance even when the filename is fixed.
export function readMemory(root) { return readFileSync(join(root, "MEMORY.md"), "utf8"); }
