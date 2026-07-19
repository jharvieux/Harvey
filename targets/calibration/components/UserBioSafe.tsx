import { escapeHtml } from "../lib/sanitize";

const STATIC_HTML = "<p>Static, hardcoded, non-user content.</p>";

// TRUE NEGATIVE (N-DSIH-PROP-ESCAPED, #613 stage-11 control): the prop is escaped before it reaches
// __html — the fixed-FP control. harvey-dangerously-set-inner-html-prop excludes escapeHtml/DOMPurify.
// sanitize/sanitizeHtml/sanitize wraps and constant string literals via metavariable-pattern — cleared.
export function SafeBio({ user }: { user: { bio: string } }) {
  return (
    <main>
      <div dangerouslySetInnerHTML={{ __html: escapeHtml(user.bio) }} />
      <footer dangerouslySetInnerHTML={{ __html: STATIC_HTML }} />
    </main>
  );
}

// TRUE NEGATIVE: safe JSX text interpolation is not a dangerouslySetInnerHTML sink at all.
export function PlainBio({ user }: { user: { bio: string } }) {
  return <div>{user.bio}</div>;
}
