import jwt from "jsonwebtoken";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// PLANTED BUG (P-JWT-DECODE-NOVERIFY): jwt.decode() reads the token's payload without checking
// its signature, and the "role" claim it returns is trusted for an authorization decision.
// Anyone can forge a token with an arbitrary "role" claim (no signing key needed) because the
// signature is never verified — this is not a real auth check.
//
// PLANTED BUG (P-CORS-REFLECT-ORIGIN): Access-Control-Allow-Origin is set to the request's own
// Origin header verbatim, with Allow-Credentials: true — no allowlist. Any origin can read this
// response with the victim's cookies attached. Contrast lib/cors-allowlist.js (N-CORS-ALLOWLIST),
// which checks Origin against an explicit allowlist before echoing it.
export function middleware(req: NextRequest) {
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  const claims = jwt.decode(token ?? "") as { role?: string } | null;
  if (claims?.role !== "admin") return NextResponse.next();

  const res = NextResponse.next();
  res.headers.set("Access-Control-Allow-Origin", req.headers.get("origin"));
  res.headers.set("Access-Control-Allow-Credentials", "true");
  return res;
}

// PLANTED BUG (P-MW-MATCHER-EXCLUDES-API, #132): the negative-lookahead excludes any path
// starting with "api" (as well as _next assets) from ever running this middleware — so
// pages/api/admin/dashboard.js, which has no auth check of its own (see that file), is reachable
// directly with no gate at all, even though this middleware looks like the app's auth layer.
// Contrast lib/middleware-matcher-safe.ts (N-MW-MATCHER-INCLUDES-API), whose matcher has no "api"
// exclusion.
export const config = {
  matcher: "/((?!api|_next/static|_next/image|favicon.ico).*)",
};
