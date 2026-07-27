import express from "express";

// OWASP Nodejs Security CS, Server Security: "Remove or obfuscate the X-Powered-By header". The
// disable is absent from the module that builds the app, so every response advertises the framework.
// The sheet's companion line — "use helmet middleware" — is scored separately and declined by design
// (#1204); its fixture is security-headers-by-hand.ts.
const app = express();

app.get("/healthz", (_req, res) => res.send("ok"));

export default app;
