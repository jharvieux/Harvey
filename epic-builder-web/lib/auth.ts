// Operator auth (design §6). Two modes behind one seam — resolveUserId() returns the partition key that
// scopes storage (§4), or null when the request is not authenticated:
//   - shared-secret (default, single-instance MVP): a signed, httpOnly, SameSite=Strict cookie set by a
//     constant-time password check; the fixed partition key is "operator".
//   - Supabase Auth (EPIC_BUILDER_AUTH=supabase, multi-user path; #103): the Supabase access token is
//     verified server-side and the authenticated user's id becomes the partition key.
// Secrets and keys are server env vars, never sent to the client and never logged.

import { createHmac, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
import { createClient } from "@supabase/supabase-js";

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

function sharedSecretUserId(token: string | undefined): string | null {
  if (!token) return null;
  const [value, mac] = token.split(".");
  if (value !== VALUE || !mac) return null;
  return constantTimeEqual(mac, sign(VALUE)) ? VALUE : null;
}

// The slice of the supabase-js auth client this uses. Production passes the real client; tests a fake.
export interface SupabaseAuthLike {
  auth: {
    getUser(jwt: string): PromiseLike<{ data: { user: { id: string } | null }; error: unknown }>;
  };
}

// Verify a Supabase access token and return its user id (the storage partition key), or null. Pure and
// injectable so it is unit-tested with a mocked client — no live Supabase in CI.
export async function resolveSupabaseUserId(
  token: string | undefined,
  client: SupabaseAuthLike,
): Promise<string | null> {
  if (!token) return null;
  const { data, error } = await client.auth.getUser(token);
  if (error || !data.user) return null;
  return data.user.id;
}

function supabaseAuthClient(): SupabaseAuthLike {
  const url = process.env.SUPABASE_URL;
  const anonKey = process.env.SUPABASE_ANON_KEY;
  if (!url || !anonKey) throw new Error("SUPABASE_URL and SUPABASE_ANON_KEY are required for Supabase auth");
  return createClient(url, anonKey, { auth: { persistSession: false } });
}

// The authenticated user's id (storage partition key), or null. The seam every route and the app shell
// gate on.
export async function resolveUserId(): Promise<string | null> {
  const jar = await cookies();
  if (process.env.EPIC_BUILDER_AUTH === "supabase") {
    const cookieName = process.env.SUPABASE_AUTH_COOKIE ?? "sb-access-token";
    return resolveSupabaseUserId(jar.get(cookieName)?.value, supabaseAuthClient());
  }
  return sharedSecretUserId(jar.get(COOKIE)?.value);
}

export async function isAuthenticated(): Promise<boolean> {
  return (await resolveUserId()) !== null;
}
