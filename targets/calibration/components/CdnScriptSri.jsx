// TRUE NEGATIVE (N-SRI-PRESENT): the same third-party CDN script, pinned with a Subresource
// Integrity hash and crossOrigin — a tampered file fails the hash check and won't execute.
// harvey-missing-sri excludes any <script> carrying an integrity attribute — cleared.
export function Analytics() {
  return (
    <script
      src="https://cdn.example.com/analytics/v3/widget.js"
      integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
      crossOrigin="anonymous"
    ></script>
  );
}
