import { sanitizeHtml } from "../lib/sanitize";

const STATIC_BIO = "<p>Calibration target. Intentionally vulnerable. Do not deploy.</p>";

// N-DSIH-SANITIZED (NEGATIVE — must NOT be flagged): two benign dangerouslySetInnerHTML
// uses — one on a sanitizer-wrapped value, one on a constant string literal. Single-file
// SAST FPs here (it can't see the sanitizer); the rule must clear sanitized/constant HTML.
export default function About({ markdownHtml }) {
  return (
    <main>
      <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(markdownHtml) }} />
      <footer dangerouslySetInnerHTML={{ __html: STATIC_BIO }} />
    </main>
  );
}
