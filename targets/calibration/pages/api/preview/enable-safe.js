import { draftMode } from "next/headers";

// TRUE NEGATIVE (N-DRAFTMODE-SECRET-CHECKED, #134): the same preview-enable action, but it
// validates a shared secret token against the environment before flipping on draft mode — an
// unauthenticated caller without the secret gets a 401 and draftMode().enable() never runs.
export default function handler(req, res) {
  if (req.query.secret !== process.env.PREVIEW_SECRET) {
    return res.status(401).json({ error: "invalid preview secret" });
  }
  draftMode().enable();
  res.status(200).json({ preview: true });
}
