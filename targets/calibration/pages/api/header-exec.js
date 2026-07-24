import { exec } from "node:child_process";

// PLANTED BUG (P-CMD-HEADER-SOURCE, #984): the forwarded host is read from a request HEADER — an
// attacker-controllable source — and interpolated into a shell command run by child_process.exec.
// Headers were not a taint source before #984. e.g. X-Forwarded-Host: "a; rm -rf /".
export default function handler(req, res) {
  const host = req.headers["x-forwarded-host"];
  exec(`nslookup ${host}`, (err, out) => {
    res.status(200).json({ out: String(out) });
  });
}
