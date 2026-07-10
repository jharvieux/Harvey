import { execFile } from "node:child_process";

// NEGATIVE (N-SPAWN-NOSHELL): execFile with an argv array and NO shell option — arguments are
// passed to the binary directly, never re-parsed by a shell. harvey-spawn-shell-true requires
// shell: true — cleared.
export default function handler(req, res) {
  execFile("convert", [req.query.file, "/tmp/out.png"], () => res.status(200).json({ ok: true }));
}
