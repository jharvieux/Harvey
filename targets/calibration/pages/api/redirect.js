import { z } from "zod";

// Post-action redirect (e.g. "return to where you came from").
const schema = z.object({
  // PLANTED BUG (open redirect): z.string().url() only checks the string is a
  // well-formed URL — it does NOT restrict the host. https://evil.example/phish
  // passes validation, so this is an open redirect (and SSRF-shaped if fetched
  // server-side). A safe version needs a host allowlist.
  url: z.string().url(),
});

export default function handler(req, res) {
  const parsed = schema.safeParse(req.query);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid url" });
  }

  res.redirect(302, parsed.data.url);
}
