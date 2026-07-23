// NEGATIVE CONTROL (SERVICE-JWT-UNVERIFIED must stay not-vulnerable): the same service-JWT-gated
// endpoint, but it VERIFIES the RS256 signature against the service issuer's public key before
// trusting the role claim. A forged `alg:none` token has no valid RSA signature (and its `alg` is not
// RS256), so it is rejected 401 -> unproven.
import { createPublicKey, verify } from "node:crypto";

export const dynamic = "force-dynamic";

// The service issuer's RS256 public key. Verification needs only the public half; the matching
// private key is deliberately NOT in this repo, so no valid service token can be minted from source.
const SERVICE_JWT_PUBLIC_KEY = createPublicKey(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4UVM5sgcDIVWmYR3zfJ
BGXlNFJTp1dq4+P5XIUvM/0fQ4q138JBQeDjJeXJDo0AcChbF/EzN6Cbd0bbA3Bt
IowiCO7LUolIHl2hW0Q6tkvFZENNpNpWunLjhxoOgjGWvwmahbMJlWQ/ZSINye63
l8tbaAqedXIzJyek7dLx2WEAPqt9rMrzMzgdtJEeEI2E16GGvn9B0XReAjVMk3Kx
vGR1Px6e7eZod6ANWEhlO/KfBh9XYsaMAqWX6PY2vkzJdbCjiCGLpATPdj8QwXT/
vHE6JLAjb6jfXAtIcj8yU3J2AUuip5x1b2h+BORfjTxbZs6jh+K69cHbyN1Mm6jN
oQIDAQAB
-----END PUBLIC KEY-----`);

function verifyRs256(bearer) {
  const token = bearer.replace(/^Bearer\s+/i, "");
  const [headerB64, payloadB64, sigB64] = token.split(".");
  if (!headerB64 || !payloadB64 || !sigB64) return null;
  const header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
  if (header.alg !== "RS256") return null; // reject alg:none / algorithm-confusion tokens
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);
  const signature = Buffer.from(sigB64, "base64url");
  if (!verify("RSA-SHA256", signingInput, SERVICE_JWT_PUBLIC_KEY, signature)) return null;
  return JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
}

export async function GET(request) {
  const authorization = request.headers.get("authorization") ?? "";
  const claims = verifyRs256(authorization);
  if (!claims || claims.role !== "service") return new Response("unauthorized", { status: 401 });

  return Response.json({ ingested: true, queueDepth: 42 });
}
