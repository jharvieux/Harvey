import express from "express";

// OWASP Nodejs Security CS, Application Security: "Use hpp middleware to prevent HTTP Parameter
// Pollution attacks." Express parses a repeated query parameter into an ARRAY, so `?role=user&role=admin`
// makes req.query.role a string[] while this code treats it as a string. The `.includes` check then
// tests array membership rather than string content and the comparison silently changes meaning.
const app = express();

app.get("/promote", (req, res) => {
  const role = req.query.role as string;
  if (role.includes("admin")) return res.status(403).send("no");
  return res.send(`role=${role}`);
});

export default app;
