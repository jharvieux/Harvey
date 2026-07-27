import express from "express";

// OWASP Nodejs Security CS, Application Security: "Set request size limits via middleware for
// different content types." express.json() with no `limit` accepts the framework default and this
// raw handler accepts an unbounded body, so one request can exhaust process memory.
const app = express();

app.use(express.json());

app.post("/ingest", (req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));
  req.on("end", () => res.json({ bytes: Buffer.concat(chunks).length }));
});

export default app;
