import fs from "fs";
import path from "path";

// N-FS-STATIC (NEGATIVE — must NOT be flagged): a static, derived-safe file read (a fixed
// path joined to __dirname), plus an unrelated method named .open() that has nothing to do
// with the filesystem. eslint-plugin-security detect-non-literal-fs-filename FPs on both;
// Harvey requires taint-from-request AND a real fs/child_process receiver before flagging.
export function readConfig() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "config.json"), "utf8"));
}

export function openWidget(widget) {
  return widget.open();
}
