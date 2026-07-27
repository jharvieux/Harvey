import express from "express";

// N-BODY-LIMIT-SET (negative for P-OWASP-NODE-BODY-LIMIT): an explicit limit option is set, so
// the framework default no longer applies.
const app = express();

app.use(express.json({ limit: "100kb" }));

export default app;
