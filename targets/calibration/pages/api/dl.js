import fs from "node:fs";
import path from "node:path";

// N-PATH-BASENAME (NEGATIVE — must NOT be flagged): the untrusted filename is sanitized with
// path.basename, which strips every directory component (../ included) before it is joined into
// the base dir — no traversal. The path-traversal rule registers path.basename as a sanitizer.
export default function handler(req, res) {
  const safe = path.basename(req.query.f);
  const body = fs.readFileSync(path.join("/var/data/uploads", safe), "utf8");
  res.status(200).send(body);
}
