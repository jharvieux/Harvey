import fs from "node:fs";
import path from "node:path";

// PLANTED BUG (P-PATH-TRAVERSAL): `name` is untrusted and joined into a filesystem path, then
// read and returned — path traversal (../ escapes the uploads dir). Review tier.
// e.g. name=../../../../etc/passwd
export default function handler(req, res) {
  const { name } = req.query;

  const target = path.join("/var/data/uploads", name);
  const body = fs.readFileSync(target, "utf8");

  res.status(200).send(body);
}
