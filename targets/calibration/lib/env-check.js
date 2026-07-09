// TRUE NEGATIVE (N-NODE-ENV-PROD): reads NODE_ENV to branch dev-only logic; never assigns it.
// harvey-node-env-not-prod only matches a literal assignment (process.env.NODE_ENV = ...).
if (process.env.NODE_ENV !== "production") {
  console.log("dev-only diagnostics enabled");
}
