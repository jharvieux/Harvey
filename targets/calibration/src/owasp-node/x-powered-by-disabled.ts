import express from "express";

// #1204 negative: same app shape as x-powered-by-exposed.ts, but the constructing module turns the
// header off, so the review-tier check must stay silent here.
const app = express();
app.disable("x-powered-by");

app.get("/healthz", (_req, res) => res.send("ok"));

export default app;
