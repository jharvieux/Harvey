import cors from "cors";
import express from "express";

// NEGATIVE (N-CORS-EXPRESS-ORIGINTRUE-NOCREDS, #663): origin: true with NO credentials — the
// #663 branch requires credentials:true alongside origin:true, same as the #614 wildcard branch,
// so this stays dark. Regression guard that the origin:true branch still requires both keys.
const app = express();
app.use(cors({ origin: true }));
export default app;
