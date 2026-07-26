import { admin } from "../../lib/supabaseAdmin";

// INTENDED NEGATIVE (N-ZERO-ROW-TENANT-SCOPE): two .eq() filters and no .select(), but neither
// filter compares against a literal state name — this is tenant scoping, not a compare-and-swap.
// There is no lost-race outcome to distinguish, so harvey-zero-row-update must stay silent. The
// { error } tuple IS checked, so harvey-unchecked-mutation stays silent too.
export default async function handler(req, res) {
  const { error } = await admin
    .from("workspaces")
    .update({ name: req.body.name })
    .eq("tenant_id", req.session.tenantId)
    .eq("id", req.body.workspaceId);

  if (error) return res.status(500).json({ error: "rename failed" });

  return res.status(200).json({ renamed: true });
}
