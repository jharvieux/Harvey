// ADVERSARIAL POSITIVE for #1237(a)'s loop-copy sanitizer
// (P-OWASP-REACT-PROP-LOOP-ATTACKER-ALLOWLIST). Structurally identical to the safe form in
// prop-spread-loop-allowlist.tsx apart from WHERE the key list comes from — the untrusted object
// itself — which is exactly the difference the sanitizer has to read. A first attempt that excluded
// only `Object.keys(...)` cleared this one silently (MEASURED 2026-07-31); constraining the
// allowlist to a bare identifier is what brings it back.

import { Field } from "./field";

export function ProfileFormLoopAttackerAllowlist({ search }: { search: URLSearchParams }) {
  const raw = JSON.parse(search.get("fieldProps") ?? "{}");
  const safe: Record<string, unknown> = {};
  for (const k of raw.fields) safe[k] = raw[k];
  return <Field {...safe} />;
}
