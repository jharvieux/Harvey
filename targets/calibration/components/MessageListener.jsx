import { useEffect, useState } from "react";

// PLANTED BUG (P-POSTMESSAGE-NO-ORIGIN): a window 'message' listener that trusts event.data with no
// event.origin check — any page (or a malicious iframe) can post data straight into app state.
// Semgrep harvey-postmessage-no-origin (listener callback has no .origin reference) → review.
export function ThemeSync() {
  const [theme, setTheme] = useState("light");
  useEffect(() => {
    window.addEventListener("message", (e) => setTheme(e.data.theme));
  }, []);
  return <div data-theme={theme} />;
}
