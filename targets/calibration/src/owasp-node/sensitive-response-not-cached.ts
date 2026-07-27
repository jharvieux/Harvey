import type { NextApiRequest, NextApiResponse } from "next";

// N-SENSITIVE-CACHE-SAFE (negative for P-OWASP-NODE-SENSITIVE-CACHE): the same identity-reading
// handler shape, but Cache-Control is private/no-store — a shared proxy/CDN must not cache this.
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const userId = req.headers["x-user-id"];
  res.setHeader("Cache-Control", "private, no-store");
  res.json({ userId, balanceCents: 1234 });
}
