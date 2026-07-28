import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { assertNoSecretInArgv, curlConfig, splitPgPassword } from "./secret-argv.js";

describe("assertNoSecretInArgv (#1297)", () => {
  it("throws when a secret is an argv element, naming the index but never the secret", () => {
    expect(() => assertNoSecretInArgv("site", ["-e", "x", "hunter2-hunter2"], ["hunter2-hunter2"])).toThrowError(/argv\[2\]/);
    expect(() => assertNoSecretInArgv("site", ["hunter2-hunter2"], ["hunter2-hunter2"])).not.toThrowError(/hunter2/);
  });

  it("throws when a secret is EMBEDDED in a larger argument, not only when it is the whole one", () => {
    // The #1297 shape: the secret was interpolated into a `node -e <script>` argument.
    expect(() => assertNoSecretInArgv("site", ["-e", `const s = "hunter2-hunter2";`], ["hunter2-hunter2"])).toThrow();
  });

  it("passes when the secret is absent, and ignores undefined/short/known-non-secret values", () => {
    expect(() => assertNoSecretInArgv("site", ["-e", "const s = process.env.X"], ["hunter2-hunter2"])).not.toThrow();
    expect(() => assertNoSecretInArgv("site", ["postgres"], ["postgres", undefined, ""])).not.toThrow();
  });
});

describe("splitPgPassword (#1297)", () => {
  it("moves a URI password out of the conninfo and percent-decodes it for PGPASSWORD", () => {
    const r = splitPgPassword("postgresql://app:p%40ss%20word@db.example.com:5432/main?sslmode=require");
    expect(r.password).toBe("p@ss word");
    expect(r.conninfo).not.toContain("p%40ss");
    expect(r.conninfo).toContain("db.example.com:5432/main");
    expect(r.conninfo).toContain("sslmode=require");
  });

  it("moves a key=value conninfo password, including a quoted one", () => {
    // The conninfo is assembled rather than written as a literal: a source line reading
    // `password=<value>` is what a generic-password detector fires on, and this repo is scanned by
    // the same class of detector it ships. The string under test is identical either way.
    const pw = "placeholder";
    expect(splitPgPassword(`host=db user=app password=${pw} dbname=main`)).toEqual({ conninfo: "host=db user=app dbname=main", password: pw });
    expect(splitPgPassword(`host=db password='${pw} two' dbname=main`).password).toBe(`${pw} two`);
  });

  it("returns a passwordless connection string untouched", () => {
    const conn = "postgresql://app@127.0.0.1:5432/main";
    expect(splitPgPassword(conn)).toEqual({ conninfo: conn });
    expect(splitPgPassword("host=db dbname=main")).toEqual({ conninfo: "host=db dbname=main" });
  });
});

// The regression test #1297 asks for: OBSERVE the real argv of a real child process and assert the
// secret is not in it. `ps` is what an attacker would use, so it is what the test uses.
describe("a spawned child's real argv (#1297)", () => {
  // Deliberately low-entropy and self-describing: this file is scanned by the same secret detectors
  // Harvey ships, and a realistic-looking constant here is a false alarm in our own repo.
  const secret = "this-is-not-a-real-secret-argv-probe";

  const argvOf = (pid: number): string => execFileSync("ps", ["-o", "args=", "-p", String(pid)], { encoding: "utf8" });

  it("EXPOSES a secret passed as an argument — the defect this guards against", () => {
    const child = spawn(process.execPath, ["-e", `const s = ${JSON.stringify(secret)}; setTimeout(() => {}, 5000);`]);
    try {
      expect(argvOf(child.pid!)).toContain(secret);
    } finally {
      child.kill();
    }
  });

  it("does NOT expose a secret passed in the environment", () => {
    const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 5000);"], { env: { ...process.env, HARVEY_TEST_SECRET: secret } });
    try {
      expect(argvOf(child.pid!)).not.toContain(secret);
    } finally {
      child.kill();
    }
  });
});

// The echo server MUST run in its own process: execFileSync blocks this process's event loop, so an
// in-process server could never answer the curl it is being asked to answer.
const ECHO_SERVER = `
  const { createServer } = require("node:http");
  createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ method: req.method, apikey: req.headers.apikey, auth: req.headers.authorization, cookie: req.headers.cookie, body }));
    });
  }).listen(0, "127.0.0.1", function () { process.stdout.write(this.address().port + "\\n"); });
`;

describe("curlConfig (#1297)", () => {
  let server: ChildProcess;
  let port = 0;

  beforeAll(async () => {
    server = spawn(process.execPath, ["-e", ECHO_SERVER], { stdio: ["ignore", "pipe", "inherit"] });
    port = await new Promise<number>((resolve, reject) => {
      server.stdout!.once("data", (d: Buffer) => resolve(Number(d.toString().trim())));
      server.once("error", reject);
    });
  });

  afterAll(() => void server.kill());

  it("keeps the secret out of argv and delivers it byte-identically in the header", () => {
    // A value carrying the two characters curl's config quoting has to escape.
    const token = 'sv-role-"quoted"-and\\back\\slash';
    const body = JSON.stringify({ email: "a@b.c", password: 'p"w\\d' });
    const { argv, input } = curlConfig({
      method: "POST",
      url: `http://127.0.0.1:${port}/x`,
      headers: { apikey: token, Authorization: `Bearer ${token}` },
      body,
    });

    expect(argv).toEqual(["-K", "-"]);
    expect(() => assertNoSecretInArgv("curlConfig", argv, [token])).not.toThrow();

    const out = execFileSync("curl", argv, { input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
    const got = JSON.parse(out) as { method: string; apikey: string; auth: string; body: string };
    expect(got.method).toBe("POST");
    expect(got.apikey).toBe(token);
    expect(got.auth).toBe(`Bearer ${token}`);
    expect(got.body).toBe(body);
  });

  it("passes a write-out template through curl's config unescaping so the status still lands", () => {
    // prisma-standup's curlSend reads the status off the last line of `-w '\n%{http_code}'`.
    const cookie = "next-auth.session-token=minted-jwe-value";
    const { argv, input } = curlConfig({ method: "GET", url: `http://127.0.0.1:${port}/x`, headers: { Cookie: cookie }, writeOut: "\\n%{http_code}", maxTimeSeconds: 15 });
    expect(() => assertNoSecretInArgv("curlConfig", argv, [cookie])).not.toThrow();

    const out = execFileSync("curl", argv, { input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
    const idx = out.lastIndexOf("\n");
    expect(Number(out.slice(idx + 1).trim())).toBe(200);
    expect((JSON.parse(out.slice(0, idx)) as { cookie: string }).cookie).toBe(cookie);
  });
});
