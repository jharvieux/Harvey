// PLANTED BUG (P-MISSING-SERVER-ONLY): this module reads a server secret from process.env but
// has no "import 'server-only'" guard, so nothing stops an accidental import from a Client
// Component pulling it (and the secret) into the browser bundle.
export function getApiSecret() {
  return process.env.INTERNAL_API_SECRET;
}
