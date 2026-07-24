import { pool } from "../../lib/db";

// N-METHODFORM-PARAM-QUERY (NEGATIVE — must NOT be flagged, #987): the method-form header value
// req.get('x-tenant-id') is passed as a bound $1 parameter, never interpolated. The new method-form
// source must not FP on a parameterized query. Regression guard for the #987 sources.
export default async function handler(req, res) {
  const tenant = req.get("x-tenant-id");
  const { rows } = await pool.query("select id from docs where tenant_id = $1", [tenant]);
  res.status(200).json(rows);
}
