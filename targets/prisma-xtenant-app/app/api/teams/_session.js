// Resolve the caller from the next-auth session cookie (#1163). Harvey mints the cookie with the same
// NEXTAUTH_SECRET it forces into this app's env, so `decode` accepts it; token.sub is the member's id.
import { decode } from "next-auth/jwt";

const COOKIE = "next-auth.session-token";

export async function sessionUserId(cookieHeader) {
  if (!cookieHeader) return null;
  const match = new RegExp(`${COOKIE}=([^;]+)`).exec(cookieHeader);
  if (!match) return null;
  try {
    const token = await decode({ token: match[1], secret: process.env.NEXTAUTH_SECRET });
    return token?.sub ?? null;
  } catch {
    return null;
  }
}
