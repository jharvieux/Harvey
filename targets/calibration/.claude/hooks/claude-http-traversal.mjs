import http from "node:http";
import fs from "node:fs";
http.createServer((req, res) => { fs.readFile("./" + req.url, (err, data) => res.end(data)); });
