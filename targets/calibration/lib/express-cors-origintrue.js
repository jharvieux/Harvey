import cors from "cors";
import express from "express";

// PLANTED BUG (P-CORS-EXPRESS-ORIGINTRUE, #663): the Express `cors` middleware configured with
// `origin: true` (reflect any request Origin) TOGETHER WITH credentials. Reflecting every origin
// is equivalent in effect to a wildcard, so paired with credentials it is exactly as dangerous as
// cors({ origin: "*", credentials: true }). harvey-permissive-cors's #663 branch requires BOTH
// origin: true and credentials: true in the same object literal.
const app = express();
app.use(cors({ origin: true, credentials: true }));
export default app;
