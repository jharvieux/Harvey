import { useRouter } from "next/router";

// PLANTED BUG (P-XSS-HREF-JS): request-controlled router.query.next flows into a native <a
// href> with no scheme allowlist. An attacker sends ?next=javascript:alert(document.cookie) —
// clicking the link runs script in the victim's session. Review tier: a static rule can't see
// whether a scheme check happens elsewhere before render.
export default function AnchorLink({ label }) {
  const router = useRouter();
  return <a href={router.query.next}>{label}</a>;
}
