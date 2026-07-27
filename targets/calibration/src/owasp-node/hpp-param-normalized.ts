import express from "express";
import { z } from "zod";

// N-HPP-ARRAY-NORMALIZED (negative for P-OWASP-NODE-HPP): the repeated-parameter array shape is
// normalized (first element taken) before the .includes() check — no `as string` cast lie.
const app = express();

app.get("/promote-safe-array", (req, res) => {
  const raw = req.query.role;
  const role = Array.isArray(raw) ? raw[0] : raw;
  if (typeof role === "string" && role.includes("admin")) return res.status(403).send("no");
  return res.send(`role=${role}`);
});

// N-HPP-SCHEMA-VALIDATED (negative for P-OWASP-NODE-HPP): a schema parse rejects/coerces the
// value instead of a bare `as string` cast.
app.get("/promote-safe-schema", (req, res) => {
  const role = z.string().parse(req.query.role);
  if (role.includes("admin")) return res.status(403).send("no");
  return res.send(`role=${role}`);
});

export default app;
