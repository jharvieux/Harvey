export interface InvoiceManager {
  totalFor(invoiceId: string): number;
}

class DefaultInvoiceManager implements InvoiceManager {
  private readonly lineItems: Record<string, number[]>;

  constructor(lineItems: Record<string, number[]>) {
    this.lineItems = lineItems;
  }

  totalFor(invoiceId: string): number {
    return (this.lineItems[invoiceId] ?? []).reduce((sum, n) => sum + n, 0);
  }
}

// The only call site in the codebase constructs this one concrete type — no second
// implementation exists, and none is planned.
export function createInvoiceManager(lineItems: Record<string, number[]>): InvoiceManager {
  return new DefaultInvoiceManager(lineItems);
}
