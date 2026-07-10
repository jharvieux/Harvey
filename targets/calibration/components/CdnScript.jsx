// PLANTED BUG (P-MISSING-SRI): a third-party CDN <script> loaded with no Subresource Integrity
// hash — if the CDN is compromised (or the URL is hijacked) arbitrary script runs in this origin.
// Add integrity="sha384-..." + crossOrigin. Semgrep harvey-missing-sri (external src, no integrity
// attribute) → review (self-hosted/first-party scripts don't need SRI, so it needs a human look).
export function Analytics() {
  return <script src="https://cdn.example.com/analytics/v3/widget.js"></script>;
}
