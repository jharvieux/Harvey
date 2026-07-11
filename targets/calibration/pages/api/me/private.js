// CACHE-CROSS-USER negative: a per-user response marked private/no-store, never shared-cached.
export default async function handler(req, res) {
  const userId = req.headers["x-user-id"] || "anon";
  res.setHeader("Cache-Control", "private, no-store");
  res.status(200).json({ tenant_id: userId });
}
