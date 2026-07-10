import { draftMode } from "next/headers";

// PLANTED BUG (P-DRAFTMODE-NO-SECRET, #134): this route flips on Next.js Draft/Preview Mode for
// ANY caller — there is no secret/token check before draftMode().enable() runs. Anyone who
// requests this route gets a draft-mode cookie and can now see unpublished/draft content on
// every page that reads it. Contrast enable-safe.js (N-DRAFTMODE-SECRET-CHECKED).
export default function handler(req, res) {
  draftMode().enable();
  res.status(200).json({ preview: true });
}
