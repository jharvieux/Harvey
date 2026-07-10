import { admin } from "../../../lib/supabaseAdmin";
import { getServerSession } from "next-auth";

// TRUE NEGATIVE (N-MW-DEFENSE-IN-DEPTH, #133): the same admin data read, but this handler ALSO
// re-checks the session and role itself — even though middleware.ts nominally covers the page
// too. If the middleware gate is ever bypassed (matcher gap, misconfiguration), this route still
// enforces authorization on its own.
export default async function handler(req, res) {
  const session = await getServerSession(req);
  if (session?.user?.role !== "admin") return res.status(403).json({ error: "forbidden" });

  const { data } = await admin.from("admin_metrics").select("*");
  res.status(200).json({ metrics: data });
}
