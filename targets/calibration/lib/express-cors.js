import cors from "cors";
import express from "express";

// PLANTED BUG (P-CORS-EXPRESS-CREDS, #614): the Express `cors` middleware configured with a
// wildcard origin TOGETHER WITH credentials. The lib reflects the origin, so any site can read
// authenticated responses cross-origin. harvey-permissive-cors → high (free count).
const app = express();
app.use(cors({ origin: "*", credentials: true }));
export default app;
