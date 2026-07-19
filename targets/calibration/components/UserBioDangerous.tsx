// PLANTED BUG (P-DSIH-PROP, #613): a component prop carrying user-controlled HTML reaches
// dangerouslySetInnerHTML with no sanitizer — stored XSS. The stored rule keys on a Supabase select
// and the reflected rule on request sources; neither saw the prop/param source. harvey-dangerously-
// set-inner-html-prop → review.
export function UserBio({ user }: { user: { bio: string } }) {
  return <div dangerouslySetInnerHTML={{ __html: user.bio }} />;
}

// Same shape via a bare identifier parameter (unsanitized markdown passthrough).
export function Markdown({ html }: { html: string }) {
  return <article dangerouslySetInnerHTML={{ __html: html }} />;
}
