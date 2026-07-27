// OWASP React Security CS (draft), SSR Security: "Validate User Input Before Server-Side Fetch
// Calls". The route param is interpolated straight into an internal-network URL executed on the
// server, so `../../` or an absolute-URL payload redirects the fetch at the cloud metadata endpoint.
// Same defect class as the App Router SSRF fixture, reached through a Server Component page rather
// than a route handler.

import { Product } from "./product";

export default async function ProductPage({ params }: { params: { id: string } }) {
  const res = await fetch(`http://internal-api.company.internal/products/${params.id}`);
  return <Product data={await res.json()} />;
}

export async function ProductPageValidated({ params }: { params: { id: string } }) {
  if (!/^\d+$/.test(params.id)) throw new Error("Invalid product ID");
  const res = await fetch(`http://internal-api.company.internal/products/${params.id}`);
  return <Product data={await res.json()} />;
}
