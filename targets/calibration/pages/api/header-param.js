import { pool } from "../../lib/db";

// N-HEADER-PARAM-QUERY (NEGATIVE — must NOT be flagged, #984): the header value is passed as a
// BOUND parameter ($1), never interpolated into the SQL text. Adding cookies/headers as taint
// sources (#984) must not flag a parameterized query — the tainted value is in the params array,
// not the (untainted) SQL string. Regression guard mirroring N-PARAM-QUERY for the new sources.
export default async function handler(req, res) {
  const tenant = req.headers["x-tenant-id"];
  const { rows } = await pool.query("select id from docs where tenant_id = $1", [tenant]);
  res.status(200).json(rows);
}
