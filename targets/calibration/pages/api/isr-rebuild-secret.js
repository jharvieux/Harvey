// TRUE NEGATIVE (N-ISR-REVALIDATE-SECRET): the same on-demand revalidation, but the handler
// compares req.query.secret against a server-side secret and bails out before revalidating.
// harvey-isr-revalidate-nosecret excludes any handler that references req.query.secret — cleared.
export default async function handler(req, res) {
  if (req.query.secret !== process.env.REVALIDATE_SECRET) {
    return res.status(401).json({ message: "invalid token" });
  }
  await res.revalidate(req.query.path);
  res.json({ revalidated: true });
}
