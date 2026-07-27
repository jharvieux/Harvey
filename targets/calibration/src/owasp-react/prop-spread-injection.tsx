// OWASP React Security CS (draft), XSS Prevention: "Avoid Prop Injection via the Spread Operator".
// Spreading an untrusted object lets the caller inject props the component never meant to accept —
// including dangerouslySetInnerHTML, which is a direct XSS sink that JSX escaping does not cover.

import { Field } from "./field";

export function ProfileForm({ search }: { search: URLSearchParams }) {
  const userInput = JSON.parse(search.get("fieldProps") ?? "{}");
  return <Field {...userInput} />;
}

const ALLOWED_PROPS = new Set(["placeholder", "disabled", "type", "aria-label"]);

export function ProfileFormAllowlisted({ search }: { search: URLSearchParams }) {
  const userInput = JSON.parse(search.get("fieldProps") ?? "{}");
  const safeProps = Object.fromEntries(
    Object.entries(userInput).filter(([key]) => ALLOWED_PROPS.has(key)),
  );
  return <Field {...safeProps} />;
}
