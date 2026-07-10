import { useEffect, useState } from "react";

// TRUE NEGATIVE (N-POSTMESSAGE-NO-ORIGIN-OK): the same listener, but it validates event.origin
// against an allowlisted host before trusting the payload. harvey-postmessage-no-origin excludes
// any callback that references .origin — cleared.
export function ThemeSync() {
  const [theme, setTheme] = useState("light");
  useEffect(() => {
    window.addEventListener("message", (e) => {
      if (e.origin !== "https://app.example.com") return;
      setTheme(e.data.theme);
    });
  }, []);
  return <div data-theme={theme} />;
}
