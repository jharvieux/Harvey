import fs from "node:fs";
import path from "node:path";

// SAFE TWIN (N-LIB-PATH-SANITIZED, #946): the exported param is confined with path.basename before
// the read, stripping every directory component — harvey-lib-path-traversal registers path.basename
// as a sanitizer, so this must stay silent.
export function readSafeFile(name) {
  return fs.readFileSync(path.join("/var/data/uploads", path.basename(name)));
}

// SAFE TWIN (N-LIB-PARAM-NOSINK, #946): an exported param that never reaches a filesystem/exec/eval
// sink. Parameter-as-source must not fire on every exported function — only ones reaching a sink.
export function greet(name) {
  return `hello ${name}`;
}
