// N-PROTO-SAFE (NEGATIVE — must NOT be flagged): a SHALLOW Object.assign of an explicitly
// picked, validated field set — no recursive merge, so a `__proto__` key can't walk into
// Object.prototype. The prototype-pollution rule must fire only on recursive merges (merge/
// defaultsDeep/mergeWith).
const DEFAULTS = { theme: "light", pageSize: 25 };

export function buildOptions(reqBody) {
  const picked = { theme: reqBody.theme, pageSize: reqBody.pageSize };
  return Object.assign({}, DEFAULTS, picked);
}
