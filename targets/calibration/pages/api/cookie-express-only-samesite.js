export default function handler(req, res) {
  res.cookie("session", req.body.sessionId, { sameSite: "strict" });
}
