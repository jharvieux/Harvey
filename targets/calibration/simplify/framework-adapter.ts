// simplify/framework-adapter.ts — BENIGN (M6-N-FRAMEWORK): an interface + factory shaped just
// like M6-P-OVERABSTRACT's manager.ts, but mandated by a framework contract, not gratuitous. The
// rubric must NOT flag this one (quality-extras.txt "FALSE POSITIVES" — "an abstraction mandated
// by a framework/library contract"). Next.js's `getServerSideProps` middleware convention
// requires a context object shaped like this even though only one page implements it today;
// collapsing it to inline would break the framework's expected call signature.
export interface PageDataAdapter<T> {
  getServerSideProps(ctx: { params: Record<string, string> }): Promise<{ props: T }>;
}

export class InvoicePageAdapter implements PageDataAdapter<{ invoiceId: string }> {
  async getServerSideProps(ctx: { params: Record<string, string> }) {
    return { props: { invoiceId: ctx.params.id ?? "" } };
  }
}
