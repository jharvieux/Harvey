import cors from "cors";
import express from "express";

// NEGATIVE (N-CORS-EXPRESS-NOCREDS, #614): a wildcard origin with NO credentials — the common,
// intended shape for a public read-only API. harvey-permissive-cors's Express branch requires
// credentials:true alongside the wildcard, so this stays dark (severity depends on credentials).
const app = express();
app.use(cors({ origin: "*" }));
export default app;
