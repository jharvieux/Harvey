// Same OWASP React CS item as rsc-fetch-unvalidated.tsx ("Validate User Input Before Server-Side
// Fetch Calls") in the ARROW spelling with a BLOCK body — the form Next.js and Remix code is
// routinely written in, and the one #1544's first cut could not see.
//
// The shared `x-request-source` block requires the RSC prop to be BOUND BY DESTRUCTURING. Its
// arrow arms were written as `(..., { ..., $RSCBIND, ... }, ...) => ...`, and MEASURED 2026-07-31
// (semgrep 1.164.0) that spelling matches an EXPRESSION-bodied arrow only: 0 matches here, 2 on
// `=> { ... }`. So this file — a typed destructured arrow whose body is a block — went silent while
// its `function` twin next door kept firing. This fixture is the guard: delete the
// `(..., { ..., $RSCBIND, ... }: $T, ...) => { ... }` arm and P-RSC-ARROW-TYPED-BINDING goes red.

import { Product } from "./product";

const ProductPageArrow = async ({ params }: { params: { id: string } }) => {
  const res = await fetch(`http://internal-api.company.internal/products/${params.id}`);
  return <Product data={await res.json()} />;
};

export default ProductPageArrow;
