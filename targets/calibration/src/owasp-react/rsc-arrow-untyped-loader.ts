// The UNTYPED destructured arrow with a block body — `export const loader = async ({ params }) =>
// { … }`. This is the ONLY spelling of the shape the real world uses. MEASURED 2026-07-31 over all
// 17 pinned corpus repos at their pinned commits (`pnpm corpus-pins`), semgrep 1.164.0, `-j 1
// --timeout 0`, 3 repeats with identical output each time: the block-bodied destructured arrow
// binding `params`/`searchParams` occurs 40 times in 33 files (carbon 12, documenso 10,
// inbox-zero 18) and the EXPRESSION-bodied twin — the only form #1544's first cut could match —
// occurs ZERO times. None of the 40 reaches a sink today, so the regression cost 0 findings and
// would have been invisible without this fixture.
//
// Guard for the `(..., { ..., $RSCBIND, ... }, ...) => { ... }` arm of the shared source block;
// the typed twin is guarded by rsc-arrow-fetch-unvalidated.tsx.

export const loader = async ({ params }) => {
  const res = await fetch(`http://internal-api.company.internal/orders/${params.orderId}`);
  return res.json();
};
