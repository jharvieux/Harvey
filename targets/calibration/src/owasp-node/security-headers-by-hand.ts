import express from "express";

// #1204 by-design boundary: this app adopts no header middleware at all and sets the same response
// headers by hand. It is CORRECT, and Harvey does not flag it for the missing library — the headers
// are checked by their effect, not by which package set them. Scored by P-OWASP-NODE-HELMET.
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
