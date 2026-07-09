// PLANTED BUG (P-NODE-ENV-NOT-PROD): NODE_ENV is force-assigned to "development" in application
// code, overriding whatever the deploy environment actually set — ships dev-mode behavior
// (verbose errors, disabled optimizations) regardless of the real deploy target.
process.env.NODE_ENV = "development";

module.exports = { debugForced: true };
