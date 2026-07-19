import { NextResponse } from "next/server";

// TRUE NEGATIVE (N-CORS-OBJLIT-REFLECTED-SAFE, #601): the same object-literal headers map with
// Allow-Credentials "true", but Access-Control-Allow-Origin is a hardcoded allowlisted origin, not
// the reflected request Origin. harvey-cors-reflected-origin-object's taint source is the request
// origin; a constant string is not tainted, so the sink is never reached — cleared. Regression guard
// for the object-literal reflected rule.
export async function GET(request: Request) {
  const headers = {
    "Access-Control-Allow-Origin": "https://app.example.com",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST",
  };
  return new NextResponse(JSON.stringify({ ok: true }), { headers });
}
