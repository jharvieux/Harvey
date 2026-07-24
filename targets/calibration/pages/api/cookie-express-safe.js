// N-COOKIE-EXPRESS-SECURE (NEGATIVE — must NOT be flagged, #988): the Express res.cookie() options
// object sets HttpOnly, Secure and SameSite together. harvey-cookie-insecure-express's pattern-not
// excludes the fully-hardened form — cleared.
export default function handler(req, res) {
  const sessionId = createSession(req.body.userId);
  res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict", maxAge: 900000 });
  res.status(200).json({ ok: true });
}
