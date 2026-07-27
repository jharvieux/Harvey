import type { NextApiRequest, NextApiResponse } from "next";

// OWASP Nodejs Security CS, Server Security: "Disable caching for pages containing sensitive
// information." This authenticated response is marked publicly cacheable, so a shared proxy or CDN
// can serve one user's record to the next requester.
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const userId = req.headers["x-user-id"];
  res.setHeader("Cache-Control", "public, max-age=600");
  res.json({ userId, ssn: "redacted-in-fixture", balanceCents: 1234 });
}
