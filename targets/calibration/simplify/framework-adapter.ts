export interface PageDataAdapter<T> {
  getServerSideProps(ctx: { params: Record<string, string> }): Promise<{ props: T }>;
}

export class InvoicePageAdapter implements PageDataAdapter<{ invoiceId: string }> {
  async getServerSideProps(ctx: { params: Record<string, string> }) {
    return { props: { invoiceId: ctx.params.id ?? "" } };
  }
}
