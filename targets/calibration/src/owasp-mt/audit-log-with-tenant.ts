import { logger } from "./logger";

// The correct form of P-OWASP-MT-LOG-TENANT (#1242), plus the two lookalikes the detector has to
// stay silent on or it is unshippable. OWASP Multi-Tenant CS section 8.

// (1) The same audit record, carrying the tenant discriminator -- reconstructable per tenant.
export function recordDeletion(tenantId: string, userId: string, invoiceId: string) {
  logger.info({ tenantId, userId, action: "invoice.deleted", invoiceId });
}

// (2) A diagnostic breadcrumb, not an audit record: an actor id but no state change. Flagging this
// would put the rule on every log line in every codebase that logs a user id.
export function traceLookup(userId: string, invoiceId: string) {
  logger.debug(`resolving invoice ${invoiceId} for user ${userId}`);
}

// (3) A state change with no actor: nothing to reconstruct an access from, so this is a different
// (weaker) signal the rule deliberately leaves alone.
export function recordSweep(invoiceCount: number) {
  logger.info(`archived ${invoiceCount} invoices in the nightly sweep`);
}
