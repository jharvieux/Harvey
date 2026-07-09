import { admin } from "../../lib/supabaseAdmin";

// N-RPC-PARAM (NEGATIVE — must NOT be flagged): a PARAMETERIZED Supabase RPC. The untrusted
// value is passed as a bound argument to a normal function ('report_total'), which PostgREST
// parameterizes — never concatenated into SQL text. The SQLi-RPC rule fires only on raw-SQL
// executor RPCs (exec_sql/execute/run_sql), so this safe shape is correctly ignored.
export default async function handler(req, res) {
  const { uid } = req.query;
  const { data } = await admin.rpc("report_total", { uid });
  res.status(200).json(data);
}
