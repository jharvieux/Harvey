import * as cp from "node:child_process";

// PLANTED BUG (#2130): the namespace-import spelling remains a real shell-string sink.
export function pingFixture(target, callback) {
  return cp.exec(`ping -c 1 ${target}`, callback);
}
