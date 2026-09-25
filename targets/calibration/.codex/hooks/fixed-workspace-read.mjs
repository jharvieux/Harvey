import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Proven fixed local source (#2130): no exported argument reaches this path.
const root = dirname(fileURLToPath(import.meta.url));
export function readMemory() {
  return readFileSync(join(root, "MEMORY.md"), "utf8");
}
