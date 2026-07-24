import http from "node:http";

// PLANTED BUG (P-SSRF-HTTP-NODE, #985): a request-controlled URL is fetched via the node http
// module (http.get), not fetch() — SSRF (e.g. url=http://169.254.169.254/ hits cloud metadata).
// harvey-ssrf-fetch only matched fetch() before #985; the http/https/axios/request sinks were added.
export default function handler(req, res) {
  const target = req.query.url;
  http.get(target, (upstream) => {
    let body = "";
    upstream.on("data", (chunk) => (body += chunk));
    upstream.on("end", () => res.status(200).send(body));
  });
}
