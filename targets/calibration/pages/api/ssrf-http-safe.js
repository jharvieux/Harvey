import https from "node:https";

// N-SSRF-HTTP-FIXED (NEGATIVE — must NOT be flagged, #985): the node https client fetches a fixed,
// non-request URL — no request-tainted value reaches the sink, so harvey-ssrf-fetch's taint never
// connects. Regression guard for the new http/https/axios/request sinks.
export default function handler(req, res) {
  https.get("https://cdn.example.com/status.json", (upstream) => {
    let body = "";
    upstream.on("data", (chunk) => (body += chunk));
    upstream.on("end", () => res.status(200).send(body));
  });
}
