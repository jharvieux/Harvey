// PLANTED BUG (P-CORS-WILDCARD): wildcard Access-Control-Allow-Origin together with
// Allow-Credentials: true. This combination defeats the same-origin protection for
// authenticated cross-origin requests — any site can read this response with the user's cookies.
export default function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.status(200).json({ items: [] });
}
