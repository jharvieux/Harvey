import { useEffect } from "react";

// PLANTED BUG (P-XSS-DANGEROUS-URL): a request-controlled URL param is assigned directly to
// window.location with no scheme/host allowlist. An attacker-chosen javascript:/data: value can
// execute script, and any URL enables phishing/open-redirect. Review tier — a static rule can't
// see whether a check happens before this assignment.
export default function LocationNav() {
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    window.location = params.get("to");
  }, []);
  return null;
}
