import { useRouter } from "next/router";

// N-SEARCHPARAMS-TEXT (NEGATIVE — must NOT be flagged): the query value is rendered as React
// TEXT content (JSX auto-escapes `{value}` in a text position), never as HTML/innerHTML/an
// href/a DOM sink. None of the harvey-*-xss rules match a plain text child expression.
export default function SearchResults() {
  const router = useRouter();
  return <p>Results for: {router.query.q}</p>;
}
