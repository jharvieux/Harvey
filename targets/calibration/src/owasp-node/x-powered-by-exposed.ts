import express from "express";

// OWASP Nodejs Security CS, Server Security: "Remove or obfuscate the X-Powered-By header" and
// "Use helmet middleware to set appropriate security headers". Neither is done: no helmet, and
// `app.disable("x-powered-by")` is absent, so every response advertises the framework.
const app = express();

app.get("/healthz", (_req, res) => res.send("ok"));

export default app;
