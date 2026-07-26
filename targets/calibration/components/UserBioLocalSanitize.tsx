// PLANTED BUG (P-XSS-LOCAL-SANITIZE, #1066): the prop is wrapped in a function NAMED `sanitize`
// that is defined three lines below and returns its argument unchanged. The XSS rules excluded a
// bare `sanitize(...)` wrap by name alone, so anyone could clear a real XSS by naming a
// pass-through. The exclusion now requires an IMPORT BINDING, so this must STILL fire.
export function LocallySanitizedBio({ user }: { user: { bio: string } }) {
  return <div dangerouslySetInnerHTML={{ __html: sanitize(user.bio) }} />;
}

function sanitize(s: string) {
  return s;
}
