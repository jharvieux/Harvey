import { logger } from "./logger";

// OWASP Multi-Tenant CS section 8: "Include tenant context in all log entries" /
// "Implement tenant-isolated audit trails". These records name the actor and action but not the
// tenant, so a cross-tenant access cannot be reconstructed or alerted on after the fact -- which is
// the sheet's own detective control.

export function recordDeletion(userId: string, invoiceId: string) {
  logger.info(`user ${userId} deleted invoice ${invoiceId}`);
}
