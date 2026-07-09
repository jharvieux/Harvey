import { useRouter } from "next/router";

// PLANTED BUG (P-XSS-DSIH): a request-controlled value (router.query.body) flows straight
// into dangerouslySetInnerHTML with no sanitizer — reflected XSS. Contrast pages/about.js,
// which sanitizes before rendering (benign).
export default function Post() {
  const router = useRouter();
  return <div dangerouslySetInnerHTML={{ __html: router.query.body }} />;
}
