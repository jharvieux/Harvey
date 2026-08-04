import { createServer } from "node:http";

const frontPort = Number(process.env.PORT ?? 3000);
const ragUrl = new URL(process.env.RAG_SERVICE_URL ?? "http://127.0.0.1:3001");
if (!new Set(["127.0.0.1", "localhost", "::1"]).has(ragUrl.hostname)) {
  throw new Error(`RAG_SERVICE_URL must be loopback, got ${ragUrl.origin}`);
}

function json(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

const front = createServer((req, res) => {
  if (req.url === "/" || req.url === "/api/notes") {
    json(res, 200, { app: "front", notes: [] });
    return;
  }
  json(res, 404, { error: "not found" });
});

const rag = createServer((req, res) => {
  if (req.url === "/api/retrieve") {
    json(res, 200, [{ id: "private-chunk", text: "behind-the-gateway data" }]);
    return;
  }
  json(res, 404, { error: "not found" });
});

front.listen(frontPort, "127.0.0.1");
rag.listen(Number(ragUrl.port), ragUrl.hostname);

function stop() {
  front.close();
  rag.close();
}
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
