import { pool } from "../../lib/db";

// N-SQLI-PARSEINT (NEGATIVE — must NOT be flagged, #986): the untrusted id is coerced with
// parseInt before it is interpolated. A number cannot carry SQL metacharacters, so this is safe —
// the (a1) transformation-sanitizer subset, deterministically clearable. The unguarded twin
// (search.js, P-SQLI-CONCAT) still fires, proving the sanitizer doesn't swallow real findings.
export default async function handler(req, res) {
  const id = parseInt(req.query.id, 10);
  const sql = `select id, title from documents where id = ${id}`;
  const { rows } = await pool.query(sql);
  res.status(200).json(rows);
}
