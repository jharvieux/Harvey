import { useEffect } from "react";

// PLANTED BUG (P-XSS-HASH-OPENURL, #1223): the classic DOM-XSS shape — the URL FRAGMENT drives a
// window.location assignment. `location.hash` never reaches the server, so it is invisible to
// every server-side control and to a WAF, and it is the source most client-side XSS
// proofs-of-concept use. harvey-open-url-sink declared searchParams and router.query but not the
// fragment, so this was silent while the searchParams control on the same sink fired.
export default function HashNav() {
  useEffect(() => {
    window.location.href = location.hash.slice(1);
  }, []);
  return null;
}
