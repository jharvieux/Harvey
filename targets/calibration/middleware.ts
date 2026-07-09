import jwt from "jsonwebtoken";
import type { NextRequest } from "next/server";

// PLANTED BUG (P-JWT-DECODE-NOVERIFY): jwt.decode() reads the token's payload without checking
// its signature, and the "role" claim it returns is trusted for an authorization decision.
// Anyone can forge a token with an arbitrary "role" claim (no signing key needed) because the
// signature is never verified — this is not a real auth check.
export function middleware(req: NextRequest) {
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  const claims = jwt.decode(token ?? "") as { role?: string } | null;
  return claims?.role === "admin";
}
