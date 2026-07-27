import express from "express";
import { createWriteStream } from "node:fs";

// N-BODY-LIMIT-SET (negative for P-OWASP-NODE-BODY-LIMIT): an explicit limit option is set, so
// the framework default no longer applies.
const app = express();

app.use(express.json({ limit: "100kb" }));

// #1200 negative for the RAW-ACCUMULATOR half: same `req.on("data")` shape as the positive fixture,
// but a running byte total is compared against a ceiling and the request is destroyed past it.
const MAX_BODY_BYTES = 1_000_000;

app.post("/ingest-bounded", (req, res) => {
  const chunks: Buffer[] = [];
  let received = 0;
  req.on("data", (c: Buffer) => {
    received += c.length;
    if (received > MAX_BODY_BYTES) {
      req.destroy();
      return;
    }
    chunks.push(c);
  });
  req.on("end", () => res.json({ bytes: Buffer.concat(chunks).length }));
});

// #1200 negative, second edge: the chunk is streamed straight to disk instead of buffered, so the
// heap never grows however large the body is — an unbounded read that is not a size defect.
app.post("/ingest-streamed", (req, res) => {
  const out = createWriteStream("/tmp/upload.bin");
  req.on("data", (c: Buffer) => out.write(c));
  req.on("end", () => res.json({ ok: true }));
});

export default app;
