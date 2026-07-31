// ADVERSARIAL POSITIVE for #1237(a)'s loop-copy sanitizer (P-OWASP-REACT-PROP-LOOP-OWN-KEYS).
// The same for-of copy as prop-spread-loop-allowlist.tsx, iterating the UNTRUSTED object's OWN keys:
// every prop name is still the caller's choice, so dangerouslySetInnerHTML reaches the component.
// It must keep firing — that is what makes the sanitizer's "keys come from a named allowlist"
// constraint falsifiable rather than merely plausible. Its own file, so it cannot satisfy the
// negative's relevance check or its sibling's.

import { Field } from "./field";

export function ProfileFormLoopOwnKeys({ search }: { search: URLSearchParams }) {
  const raw = JSON.parse(search.get("fieldProps") ?? "{}");
  const safe: Record<string, unknown> = {};
  for (const k of Object.keys(raw)) safe[k] = raw[k];
  return <Field {...safe} />;
}
