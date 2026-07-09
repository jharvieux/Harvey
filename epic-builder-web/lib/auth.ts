// Shared-secret operator auth (design §6). MVP trust model: one operator, one server-side secret.
// A valid login sets a signed, httpOnly, SameSite=Strict cookie; every /api route and the app shell
// require it. Constant-time comparison; the secret and signing key are server env vars, never sent to
// the client and never logged. Production replaces this with Supabase Auth (design §6, §9; #103).

import { createHmac, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";

const COOKIE = "epic_session";
const VALUE = "operator";

function signingKey(): string {
  return process.env.EPIC_BUILDER_SESSION_SECRET ?? "dev-insecure-session-secret";
}

function sign(value: string): string {
  return createHmac("sha256", signingKey()).update(value).digest("hex");
}

function tokenFor(value: string): string {
  return `${value}.${sign(value)}`;
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function checkPassword(password: string): boolean {
  const expected = process.env.EPIC_BUILDER_PASSWORD ?? "dev-password";
  return constantTimeEqual(password, expected);
}

export function sessionCookie(): { name: string; value: string; options: Record<string, unknown> } {
  return {
    name: COOKIE,
    value: tokenFor(VALUE),
    options: { httpOnly: true, sameSite: "strict" as const, secure: true, path: "/", maxAge: 60 * 60 * 12 },
  };
}

export async function isAuthenticated(): Promise<boolean> {
  const jar = await cookies();
  const token = jar.get(COOKIE)?.value;
  if (!token) return false;
  const [value, mac] = token.split(".");
  if (value !== VALUE || !mac) return false;
  return constantTimeEqual(mac, sign(VALUE));
}
