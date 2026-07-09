// PLANTED BUG (P-COOKIE-INSECURE): the session cookie is set with no attributes at all — no
// HttpOnly (readable by injected script, i.e. XSS -> session theft), no Secure (sent over plain
// HTTP), no SameSite (rides cross-site requests).
export default function handler(req, res) {
  const sessionId = createSession(req.body.userId);
  res.setHeader("Set-Cookie", "sid=" + sessionId);
  res.status(200).json({ ok: true });
}
