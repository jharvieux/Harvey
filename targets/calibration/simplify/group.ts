// simplify/group.ts — PLANTED (M6-P-GROUPBY): a hand-rolled array group-by reduce.
// The rubric expects /simplify to name `Object.groupBy` / `Map.groupBy` (Node 21+/ES2024) or,
// if the target's runtime predates those, lodash-es `groupBy` — instead of this bespoke reduce
// (quality-extras.txt M6 "HAND-ROLLED PRIMITIVES").
export function groupBy<T, K extends string | number>(
  items: T[],
  keyFn: (item: T) => K,
): Record<K, T[]> {
  const result = {} as Record<K, T[]>;
  for (const item of items) {
    const key = keyFn(item);
    if (!result[key]) result[key] = [];
    result[key].push(item);
  }
  return result;
}
