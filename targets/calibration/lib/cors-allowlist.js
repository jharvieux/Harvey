// TRUE NEGATIVE (N-CORS-ALLOWLIST): Origin is checked against an explicit allowlist before it is
// ever echoed back — the reflected-origin shape harvey-cors-reflected-origin matches never
// appears (Access-Control-Allow-Origin is only set to the validated `origin` variable, never
// directly to req.headers.get("origin")).
const ALLOWED_ORIGINS = ["https://app.example.com", "https://admin.example.com"];

export function withCors(req, res) {
  const origin = req.headers.get("origin");
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.headers.set("Access-Control-Allow-Origin", origin);
    res.headers.set("Access-Control-Allow-Credentials", "true");
  }
  return res;
}
