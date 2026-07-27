import { useEffect } from "react";

const ALLOWED_ROUTES = ["/dashboard", "/settings", "/billing"];

// SAFE LOOKALIKE (N-XSS-HASH-ALLOWLISTED, #1223): the same fragment source and the same
// window.location sink as HashNav, gated by an exact-match allowlist with an early return, so no
// attacker-chosen scheme survives. Adding location.hash as a source without a guard model would
// have made every correctly-written fragment router a finding — the three URL sink rules carried
// NO sanitizers at all before this, which is why the guard lands with the source.
export default function HashNavAllowlisted() {
  useEffect(() => {
    const to = location.hash.slice(1);
    if (!ALLOWED_ROUTES.includes(to)) return;
    window.location.href = to;
  }, []);
  return null;
}
