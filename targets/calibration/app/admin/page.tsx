import { admin } from "../../lib/supabaseAdmin";
import { AdminDashboardClient } from "../../components/AdminDashboardClient";

// PLANTED BUG (P-CLIENT-RENDER-AUTHZ, #136): the server fetches the full admin dataset
// UNCONDITIONALLY — no role check before the query — and ships it to a Client Component whose
// only gate is a render-time `if (!isAdmin) return null` (see AdminDashboardClient.jsx). The
// data is already in the RSC payload the client received; a non-admin can read it straight out
// of devtools/the page source no matter what the UI renders. Contrast page-safe.tsx
// (N-SERVER-ROLE-CHECK), which checks the role on the server before the query ever runs.
export default async function AdminPage({ isAdmin }: { isAdmin: boolean }) {
  const { data } = await admin.from("admin_metrics").select("*");
  return <AdminDashboardClient isAdmin={isAdmin} metrics={data} />;
}
