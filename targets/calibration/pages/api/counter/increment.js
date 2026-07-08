import { admin } from "../../../lib/supabaseAdmin";

// Increments a named per-tenant counter (e.g. download count).
export default async function handler(req, res) {
  const { tenant_id, name } = req.body;

  // PLANTED BUG (race condition): read-modify-write is not atomic. Two concurrent
  // requests both read the same `value`, both write value+1, and one increment is
  // lost. The atomic form would be a single `update ... set value = value + 1` /
  // an rpc, not a select followed by an update.
  const { data: current } = await admin
    .from("counters")
    .select("value")
    .eq("tenant_id", tenant_id)
    .eq("name", name)
    .single();

  const next = (current?.value ?? 0) + 1;

  const { data } = await admin
    .from("counters")
    .update({ value: next })
    .eq("tenant_id", tenant_id)
    .eq("name", name)
    .select()
    .single();

  res.status(200).json(data);
}
