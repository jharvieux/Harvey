import { useEffect } from "react";

// PLANTED BUG (P-DOM-XSS-DOCWRITE): the URL fragment (location.hash — fully attacker-
// controlled, never sent to the server) flows straight into document.write(). document.write
// executes any <script> in its argument, so this is a near-100%-precision sink once the source
// is a URL/DOM signal. High tier (free count).
export default function Embed() {
  useEffect(() => {
    document.write(location.hash);
  }, []);
  return null;
}
