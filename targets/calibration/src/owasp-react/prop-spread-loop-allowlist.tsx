// TRUE NEGATIVE for the prop-spread rule (N-OWASP-REACT-PROP-LOOP-ALLOWLIST, #1237(a)) — the OWASP
// sheet's own remedy written IMPERATIVELY. `Object.fromEntries(Object.entries(x).filter(…))` was the
// only spelling the rule recognised, so this equally correct one was reported at High: the rule was
// flagging a fix. MEASURED 2026-07-31 before the sanitizer arm landed, it fired here.
//
// What makes it safe is that the KEY comes from a named source-level allowlist, never from the
// untrusted object — so no attacker-chosen prop name (dangerouslySetInnerHTML included) can reach
// the component. Its two adversarial siblings live in prop-spread-loop-attacker-keys.tsx, in their
// own file so neither can satisfy this row's relevance check.

import { Field } from "./field";

const ALLOWED_PROPS = ["placeholder", "disabled", "type", "aria-label"];

export function ProfileFormLoopAllowlisted({ search }: { search: URLSearchParams }) {
  const raw = JSON.parse(search.get("fieldProps") ?? "{}");
  const safe: Record<string, unknown> = {};
  for (const k of ALLOWED_PROPS) if (k in raw) safe[k] = raw[k];
  return <Field {...safe} />;
}
