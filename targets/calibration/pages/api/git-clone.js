import { execFile } from "node:child_process";

// PLANTED BUG (P-ARG-INJECTION, #983): the request-controlled repo value is passed as an argv-array
// element to execFile("git", [...]) with NO shell. This is argument injection (CWE-88), not shell
// command injection (CWE-78): a value like "--upload-pack=touch /tmp/pwned" is read by git as a
// flag. Distinct from the exec/execSync shell-string sink. harvey-argument-injection taint → review.
export default function handler(req, res) {
  const repo = req.query.repo;
  execFile("git", ["clone", repo, "/tmp/repo"], (err) => {
    res.status(200).json({ ok: !err });
  });
}
