import { admin } from "../../lib/supabaseAdmin";

// The privilege comes from the verified session (app_metadata), never from the request.
export default async function handler(req, res) {
  const {
    data: { user },
  } = await admin.auth.getUser(req.headers.authorization?.replace("Bearer ", ""));
  if (user?.app_metadata?.role === "admin") {
    await admin.from("users").update({ role: "admin" }).eq("id", req.body.userId);
    return res.status(200).json({ ok: true });
  }
  return res.status(403).json({ error: "forbidden" });
}
