import { sanitize } from "isomorphic-dompurify";

// TRUE NEGATIVE (N-XSS-IMPORT-SANITIZE, #1066): the same `sanitize(...)` wrap as
// UserBioLocalSanitize.tsx, but here the name resolves to a real library import — the shape the
// sanitizer exclusion exists to clear, and the control proving #1066 tightened it without
// deleting it.
export function LibrarySanitizedBio({ user }: { user: { bio: string } }) {
  return <div dangerouslySetInnerHTML={{ __html: sanitize(user.bio) }} />;
}
