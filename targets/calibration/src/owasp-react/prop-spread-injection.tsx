// OWASP React Security CS (draft), XSS Prevention: "Avoid Prop Injection via the Spread Operator".
// Spreading an untrusted object lets the caller inject props the component never meant to accept —
// including dangerouslySetInnerHTML, which is a direct XSS sink that JSX escaping does not cover.
// The sheet's allowlisted remedy lives in prop-spread-allowlisted.tsx, in its own file so it is
// scoreable as a negative independently of the finding this file must produce.

import { Field } from "./field";

export function ProfileForm({ search }: { search: URLSearchParams }) {
  const userInput = JSON.parse(search.get("fieldProps") ?? "{}");
  return <Field {...userInput} />;
}
