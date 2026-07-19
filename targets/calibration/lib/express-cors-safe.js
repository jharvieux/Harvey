import cors from "cors";
import express from "express";

// NEGATIVE (N-CORS-EXPRESS-ALLOWLIST, #614): credentials are allowed, but origin is an explicit
// allowlist, not "*". harvey-permissive-cors requires BOTH the wildcard origin and credentials —
// cleared. Regression guard that the Express cors() branch keys on the wildcard, not on credentials.
const app = express();
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
export default app;
