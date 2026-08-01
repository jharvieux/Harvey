const fs = require("fs");

// SAFE TWIN (N-LIB-PATH-GUARD, #1631): harvey-lib-path-traversal carried only path.basename as a
// sanitizer, so the (a2) validator-guard spelling — an anchored allowlist that rejects every `.`
// and `/` — still fired. path.basename is not the only correct containment.
export function readDoc(name) {
  if (!/^[a-z0-9-]+$/.test(name)) return null;
  return fs.readFileSync(`/srv/docs/${name}`, "utf8");
}
