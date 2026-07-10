import { spawn } from "node:child_process";

// PLANTED BUG (P-SPAWN-SHELL): spawn() with { shell: true } runs the command through /bin/sh, so
// the argv array is re-parsed by the shell — an untrusted filename can inject shell metacharacters.
// harvey-spawn-shell-true (distinct from harvey-command-injection, which matches exec/execSync).
export default function handler(req, res) {
  const child = spawn("convert", [req.query.file, "/tmp/out.png"], { shell: true });
  child.on("close", () => res.status(200).json({ ok: true }));
}
