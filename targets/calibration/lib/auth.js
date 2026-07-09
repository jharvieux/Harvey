import jwt from "jsonwebtoken";

// PLANTED BUG (P-JWT-SIGNING-SECRET): a session/JWT signing secret hardcoded in source instead
// of read from an env/secret store. The value is FAKE but high-entropy, so gitleaks
// generic-api-key matches it → review (a literal-secret heuristic, not a provider pattern:
// anyone with the source can forge valid sessions).
const JWT_SIGNING_SECRET = "hs512_9QmZ2vXcW8rNpKdLhGfYsAe4Uo1Bx6Vt0Zi7Ny5Mw3Qr8Kp2Ld6Hj4Gg1Fa";

export function issueSession(userId) {
  return jwt.sign({ sub: userId }, JWT_SIGNING_SECRET, { expiresIn: "7d" });
}
