import fs from "node:fs";
import path from "node:path";

// PLANTED BUG (P-LIB-PATH-TRAVERSAL, #946): the exported function's parameter `name` is joined into
// a filesystem read with no containment — a `../` argument escapes the base dir. Library-internal
// parameter-sourced path traversal (the @vivaxy/here / asset-cache SecBench shape). Review tier.
export function readUserFile(name) {
  return fs.readFileSync(path.join("/var/data/uploads", name));
}
