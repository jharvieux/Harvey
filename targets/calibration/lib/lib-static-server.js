import fs from "node:fs";
import http from "node:http";

// PLANTED BUG (P-LIB-HTTP-TRAVERSAL, #946): a raw node http server whose request-callback param
// (`req.url`) is concatenated into a path and read — the dominant SecBench path-traversal shape
// (`var p = "./" + req.url; fs.readFile(p)`), which Harvey's Express/Next request sources never
// modelled. Review tier.
export function serve() {
  return http.createServer((req, res) => {
    const p = "." + req.url;
    fs.readFile(p, (err, data) => res.end(data));
  });
}
