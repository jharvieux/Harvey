import jwt from "jsonwebtoken";
import { admin } from "../../../../lib/supabaseAdmin";
import { JWT_SECRET } from "../../../../lib/jwtSecret";

// PLANTED BUG (P-AUTHED-NO-ROLE-CHECK-JWT, #586): an admin route authenticated by a CUSTOM HS256 JWT
// (jwt.verify), NOT Supabase getUser/getSession — it 401s an anonymous/invalid-token caller but does
// NO role/permission check before returning every user's record. This is the SuperRedHat F-04 shape
// (app/api/admin/users), which #561's detector MISSED because its "authenticated" signal only knew
// Supabase getUser/getSession. #586 broadened the signal to any auth establishment (jwt.verify).
// harvey-authed-no-role-check (custom-auth signal) → review (High).
export async function GET(req: Request) {
  const token = req.headers.get("authorization")?.replace("Bearer ", "") ?? "";
  const decoded = jwt.verify(token, JWT_SECRET);
  if (!decoded) return new Response("Unauthorized", { status: 401 });
  const { data } = await admin.from("users").select("id, email, plan, org_id");
  return Response.json({ users: data });
}
