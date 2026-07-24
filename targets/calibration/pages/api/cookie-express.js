// PLANTED BUG (P-COOKIE-EXPRESS-INSECURE, #988): the Express res.cookie() method sets a session
// cookie with an options object that omits HttpOnly/Secure/SameSite (only maxAge). The old rule
// only matched a raw Set-Cookie header string, so this framework-idiomatic shape scored 0%.
// harvey-cookie-insecure-express → high.
export default function handler(req, res) {
  const sessionId = createSession(req.body.userId);
  res.cookie("session", sessionId, { maxAge: 900000 });
  res.status(200).json({ ok: true });
}
