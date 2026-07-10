import { admin } from "../../lib/supabaseAdmin";
import { getServerSession } from "next-auth";
import { redirect } from "next/navigation";
import { AdminDashboardClient } from "../../components/AdminDashboardClient";

// TRUE NEGATIVE (N-SERVER-ROLE-CHECK, #136): the role check happens on the SERVER, before the
// data is ever fetched — a non-admin is redirected and the admin_metrics query never runs, so
// the data never reaches the client (or the RSC payload) at all.
export default async function AdminPageSafe() {
  const session = await getServerSession();
  if (session?.user?.role !== "admin") redirect("/");

  const { data } = await admin.from("admin_metrics").select("*");
  return <AdminDashboardClient isAdmin={true} metrics={data} />;
}
