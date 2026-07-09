import { exec } from "node:child_process";

// PLANTED BUG (P-CMD-INJECTION): `f` is untrusted and interpolated into a shell command run by
// child_process.exec, which spawns /bin/sh — OS command injection. e.g. f="a.png; rm -rf /"
export default function handler(req, res) {
  const { f } = req.query;

  exec(`convert ${f} /tmp/out.png`, (err) => {
    if (err) return res.status(500).json({ error: "convert failed" });
    res.status(200).json({ ok: true });
  });
}
