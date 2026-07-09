// TRUE NEGATIVE (N-COOKIE-SECURE): the session cookie is hardened with HttpOnly, Secure, and
// SameSite. harvey-cookie-insecure's metavariable-regex requires the cookie value to contain no
// semicolon at all; this value has three (one per attribute) and is not matched.
export default function handler(req, res) {
  const sessionId = createSession(req.body.userId);
  res.setHeader("Set-Cookie", `sid=${sessionId}; HttpOnly; Secure; SameSite=Strict`);
  res.status(200).json({ ok: true });
}
