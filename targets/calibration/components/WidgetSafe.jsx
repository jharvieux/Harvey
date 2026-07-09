import { useEffect, useRef } from "react";

// N-INNERHTML-STATIC (NEGATIVE — must NOT be flagged): innerHTML assigned a constant string
// literal, never user input. harvey-dom-innerhtml fires only on router.query/location/
// searchParams sources; a hardcoded loading message clears it. (Named WidgetSafe.jsx, not the
// spec's Widget.jsx, to avoid a basename collision with the P-DOM-XSS-INNERHTML positive.)
export default function WidgetSafe() {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.innerHTML = "<strong>Loading…</strong>";
  }, []);
  return <div ref={ref} />;
}
