import jwt from "jsonwebtoken";
import { admin } from "../../../../lib/supabaseAdmin";
import { JWT_SECRET } from "../../../../lib/jwtSecret";

// TRUE NEGATIVE (N-AUTHED-ROLE-CHECKED-JWT, #586): the same custom-JWT-authenticated admin route, but
// it reads the role claim off the verified token and 403s a non-admin before returning any data.
// harvey-authed-no-role-check's pattern-not-regex clears any handler referencing a role/authz gate
// (the `.role` read, the 403 response) — must clear. Regression guard for the #586 custom-auth signal:
// confirms the broadened jwt.verify signal fires only on the missing-gate case, not a role-gated one.
export async function GET(req: Request) {
  const token = req.headers.get("authorization")?.replace("Bearer ", "") ?? "";
  const decoded = jwt.verify(token, JWT_SECRET) as { role: string };
  if (decoded.role !== "admin") return new Response("Forbidden", { status: 403 });
  const { data } = await admin.from("users").select("id, email, plan, org_id");
  return Response.json({ users: data });
}
