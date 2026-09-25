const CODE_PATTERN = /^FIXTURE:(\d+):/;

// BENIGN TWIN (#2130): RegExp.prototype.exec parses data. The receiver is a RegExp, not the
// child_process module, so this must never be classified as OS command execution.
export function parseFixtureCode(compact) {
  return CODE_PATTERN.exec(compact);
}
