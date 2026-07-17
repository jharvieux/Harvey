import { admin } from "../../../lib/supabaseAdmin";

// TRUE NEGATIVE (N-COUNTER-ATOMIC, #353): the same per-tenant counter increment, but atomic — a
// single server-side RPC does `value = value + 1` in one statement, so concurrent requests can't
// interleave a read and lose an increment. There is no select-then-update read-modify-write pair
// to flag. Contrast increment.js (P-COUNTER-RACE), which reads `value`, adds 1 in app code, and
// writes the derived value back.
export default async function handler(req, res) {
  const { tenant_id, name } = req.body;

  const { data } = await admin.rpc("increment_counter", { p_tenant_id: tenant_id, p_name: name });

  res.status(200).json(data);
}
