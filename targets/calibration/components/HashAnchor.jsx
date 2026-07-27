// PLANTED BUG (P-XSS-HASH-HREF, #1223): the fragment reaches a native <a href> with no scheme
// allowlist — `#javascript:alert(1)` runs script on click. harvey-href-js-url was NOT named in
// #1223's scope, but the same probe measured it equally blind to location.hash/.search, so it
// takes the same shared source block.
export default function HashAnchor() {
  const to = location.hash.slice(1);
  return <a href={to}>continue</a>;
}
