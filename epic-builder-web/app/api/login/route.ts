import { NextResponse } from "next/server";
import { checkPassword, sessionCookie } from "../../../lib/auth.js";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<NextResponse> {
  const { password } = (await req.json()) as { password?: string };
  if (!password || !checkPassword(password)) {
    return NextResponse.json({ error: "invalid password" }, { status: 401 });
  }
  const res = NextResponse.json({ ok: true });
  const c = sessionCookie();
  res.cookies.set(c.name, c.value, c.options);
  return res;
}
