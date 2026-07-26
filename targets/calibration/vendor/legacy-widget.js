import { execSync } from "child_process";

// PLANTED BUG (P-SEMGREP-VENDOR-SCOPE, #1066): a request-controlled value reaching a shell sink,
// in a directory semgrep's BUILT-IN default ignore set drops. MEASURED 2026-07-25 (semgrep
// 1.164.0): with only `--exclude node_modules` passed, an identical file copied into eight
// directories was analysed in three — `tests/`, `test/`, `vendor/`, `dist/` and `build/` were
// never scanned AND never listed, so their absence read as clean. `vendor/` is real shipped code.
// Harvey now passes --x-ignore-semgrepignore-files, and anything still unscanned is counted in
// SEM-SCOPE-00. This positive is the end-to-end proof: it must be FOUND, not skipped.
export default function handler(req, res) {
  execSync(`convert ${req.query.file} /tmp/out.png`);
  res.status(200).json({ ok: true });
}
