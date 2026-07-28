// #1237/#1344 ADVERSARIAL POSITIVE — the object literal is a disguise, not a filter.
//
// This is prop-spread-literal-pick.tsx's twin, and the reason that file's exclusion is sound rather
// than a quiet widening: the spread operand IS an object literal, so the structural exclusion would
// clear it, except that the literal spreads the untrusted object straight back in. Every name in
// `raw` still reaches the component, including dangerouslySetInnerHTML. It must keep firing.
//
// This is the #989/#1066 shape stated as a fixture: an exclusion that looks structural can still
// silently clear a real bug if the structure it keys on is spoofable. Here it is spoofable in
// exactly one way, and that way is planted here.

import { Field } from "./field";

export function ProfileFormLiteralRespread({ search }: { search: URLSearchParams }) {
  const raw = JSON.parse(search.get("fieldProps") ?? "{}");
  return <Field {...{ placeholder: "Name", ...raw }} />;
}
