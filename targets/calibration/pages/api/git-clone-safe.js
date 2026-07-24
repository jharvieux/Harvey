import { execFile } from "node:child_process";

// N-ARG-INJECTION-FIXED (NEGATIVE — must NOT be flagged, #983): execFile("git", [...]) with a fixed
// constant repo URL — no request-tainted value reaches the argv array, so harvey-argument-injection's
// taint never connects. Regression guard that the CWE-88 argv-array rule is taint-gated (it must not
// fire on every execFile, only on one carrying request-controlled args).
export default function handler(req, res) {
  execFile("git", ["clone", "https://github.com/example/repo.git", "/tmp/repo"], (err) => {
    res.status(200).json({ ok: !err });
  });
}
