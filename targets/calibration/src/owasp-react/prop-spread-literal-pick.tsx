// #1237/#1344 NEGATIVE — the caller cannot choose a prop NAME here.
//
// harvey-jsx-prop-spread-injection is about one thing: spreading an untrusted object lets the
// caller pick which props the component receives, including dangerouslySetInnerHTML. In this
// spelling the prop names are LITERALS IN THE SOURCE, so there is no name to inject and the
// weakness does not exist. The values are still untrusted, which is a different question and not
// XSS — `placeholder` is not a script sink.
//
// MEASURED 2026-07-27: this fired High before #1344. It was not caught by the existing negative
// (prop-spread-allowlisted.tsx) because that file uses the single `Object.fromEntries(...filter
// (...includes))` spelling the rule lists as a sanitizer, so "the planted negative stays silent"
// was satisfiable by matching one literal spelling — the #1191 lesson one level up.
//
// The paired POSITIVE is prop-spread-literal-respread.tsx: an object literal that spreads the
// untrusted object back in DOES restore name choice and must keep firing. If this file goes silent
// because the whole object-literal sink was dropped rather than because names became literal, that
// file fails — which is what makes this exclusion falsifiable rather than a quiet widening.

import { Field } from "./field";

export function ProfileFormLiteralPick({ search }: { search: URLSearchParams }) {
  const raw = JSON.parse(search.get("fieldProps") ?? "{}");
  return <Field {...{ placeholder: raw.placeholder, disabled: raw.disabled }} />;
}
