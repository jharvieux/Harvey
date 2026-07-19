import { NextResponse } from "next/server";

// PLANTED BUG (P-CORS-REFLECTED-OBJLIT, #601 CX-17): an object-literal CORS headers map reflects the
// request's Origin header verbatim into Access-Control-Allow-Origin AND sets Allow-Credentials:
// "true" — any origin can read the response with the victim's cookies. The App Router object-literal
// idiom (returned via new NextResponse(body, { headers })) that the imperative res.headers.set()
// reflected rule missed. harvey-cors-reflected-origin-object → high.
export async function GET(request: Request) {
  const origin = request.headers.get("origin");
  const headers = {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST",
  };
  return new NextResponse(JSON.stringify({ ok: true }), { headers });
}
