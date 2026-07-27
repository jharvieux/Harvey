import { NextResponse } from "next/server";

// PLANTED BUG (P-REDIRECT-JSON-BODY, #1221): the redirect target comes from the App Router JSON
// body with no host allowlist. harvey-open-redirect carried searchParams but not `await req.json()`.
export async function POST(req: Request) {
  const { next } = await req.json();
  return NextResponse.redirect(next);
}
