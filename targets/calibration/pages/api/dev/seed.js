import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-DEBUG-ENDPOINT): a seed/dev route under pages/api/dev with no auth guard.
// Anyone who finds the path can wipe and reseed data. Dev-only routes must never ship, or
// must be guarded. Caught by the leftover-auth grep (sensitive route segment + no auth call).
export default async function handler(req, res) {
  await admin.from("notes").delete().neq("id", "00000000-0000-0000-0000-000000000000");
  await admin.from("notes").insert([{ title: "seed", tenant_id: req.body.tenant_id }]);
  res.status(200).json({ seeded: true });
}
