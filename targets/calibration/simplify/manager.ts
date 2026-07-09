// simplify/manager.ts — PLANTED (M6-P-OVERABSTRACT): a single-implementation interface + factory
// wrapping one concrete class. The rubric expects /simplify to name the collapse: delete
// InvoiceManager/createInvoiceManager, export DefaultInvoiceManager's methods directly
// (quality-extras.txt M6 "OVER-ABSTRACTION" — "an interface/factory/generic with a single
// implementation or single call site... adds indirection without behavior").
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
