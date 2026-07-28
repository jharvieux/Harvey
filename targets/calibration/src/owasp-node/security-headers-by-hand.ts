import express from "express";

// #1204 by-design boundary: this app adopts no header middleware at all and sets the same response
// headers by hand. It is CORRECT, and Harvey does not flag it for the missing library — the headers
// are checked by their effect, not by which package set them. Scored by P-OWASP-NODE-HELMET, and
// since #1350 also by N-OWASP-NODE-EXPRESS-HEADERS-BY-HAND, which is the control on the effect
// check itself (express-security-headers.ts) staying an effect check: it must clear this file. Until
// #1350 the "checked by their effect" claim was true only of a next.config.js — on Express nothing
// checked them at all, which is why the effect check now exists rather than the claim being dropped.
const app = express();
app.disable("x-powered-by");

app.use((_req, res, next) => {
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  next();
});

app.get("/status", (_req, res) => res.send("ok"));

export default app;
