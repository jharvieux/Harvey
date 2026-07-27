// TRUE NEGATIVE for the prop-spread rule (N-OWASP-REACT-PROP-ALLOWLIST) — the sheet's own remedy.
// The same untrusted object, filtered through an explicit allowlist of prop names before it is
// spread, so the caller can no longer choose which props the component receives. This is the form
// harvey-jsx-prop-spread-injection must clear to be shippable at all: without it the rule flags
// every spread in every React codebase. Kept out of the positive's file because a negative sharing
// a location with a firing positive can only be scored trivially.

import { Field } from "./field";

const ALLOWED_PROPS = new Set(["placeholder", "disabled", "type", "aria-label"]);

export function ProfileFormAllowlisted({ search }: { search: URLSearchParams }) {
  const userInput = JSON.parse(search.get("fieldProps") ?? "{}");
  const safeProps = Object.fromEntries(
    Object.entries(userInput).filter(([key]) => ALLOWED_PROPS.has(key)),
  );
  return <Field {...safeProps} />;
}
