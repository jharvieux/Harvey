// PLANTED BUG (SERVICE-JWT-UNVERIFIED): an endpoint gated on a service JWT in the Authorization
// header, but it DECODES the token instead of verifying its signature — so a forged `alg:none` token
// claiming role "service" is accepted. The seam probe GETs it with a forged unsigned service JWT and
// gets a 200 -> proven.
export const dynamic = "force-dynamic";

function decodeUnverified(bearer) {
  const token = bearer.replace(/^Bearer\s+/i, "");
  const payload = token.split(".")[1] ?? "";
  try {
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return {};
  }
}

export async function GET(request) {
  const authorization = request.headers.get("authorization") ?? "";
  const claims = decodeUnverified(authorization);
  // Trusts the decoded claim with no signature check — the bug.
  if (claims.role !== "service") return new Response("unauthorized", { status: 401 });

  return Response.json({ ingested: true, queueDepth: 42, service: claims.iss ?? "unknown" });
}
