import { describe, expect, it } from "vitest";
import { detectPropOvershareFindings } from "./prop-overshare.js";

// #1252 — OWASP React Security CS (draft), Sensitive Data Exposure: "Minimize Sensitive Data in
// Component State and Props". The intent under test is the CONJUNCTION, because either half alone
// is useless: a sensitive-name list on its own flags every user type in the repo, and "an object was
// passed as a prop" on its own flags most of a React codebase. Every case below pins one half while
// holding the other fixed.

const SENSITIVE = `interface Account {
  name: string;
  avatarUrl: string;
  ssn: string;
}
`;
const BENIGN = `interface Account {
  name: string;
  avatarUrl: string;
  email: string;
}
`;

function run(text: string, path = "src/account-header.tsx") {
  return detectPropOvershareFindings([{ path, text }]);
}

describe("prop-overshare (#1252 — whole object with a sensitive field passed as a prop)", () => {
  it("flags a whole object handed to a component as one named prop", () => {
    const findings = run(`export function AccountHeader({ account }: { account: Account }) {
  return <Avatar user={account} />;
}
${SENSITIVE}`);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "Medium", precisionTier: "review" });
    expect(findings[0]?.taxonomy).toBe("Sensitive fields in props");
    expect(findings[0]?.evidence).toContain("`ssn`");
  });

  it("flags the JSX spread spelling of the same overshare", () => {
    const findings = run(`export function AccountHeader({ account }: { account: Account }) {
  return <Avatar {...account} />;
}
${SENSITIVE}`);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("{...account}");
  });

  // The syntactic half held fixed, the naming half flipped. If this ever fires the rule has become
  // "any object passed as a prop", which on a real repo is hundreds of rows.
  it("stays silent when the whole object is passed but nothing in its type is sensitive", () => {
    expect(
      run(`export function AccountHeader({ account }: { account: Account }) {
  return <Avatar user={account} />;
}
${BENIGN}`),
    ).toEqual([]);
  });

  // The naming half held fixed, the syntactic half flipped — the sheet's own remedy.
  it("stays silent when only the rendered fields are projected out", () => {
    expect(
      run(`export function AccountHeader({ account }: { account: Account }) {
  const { name, avatarUrl } = account;
  return <Avatar name={name} avatarUrl={avatarUrl} />;
}
${SENSITIVE}`),
    ).toEqual([]);
  });

  it("stays silent on an intrinsic element, which takes no component props", () => {
    expect(
      run(`export function AccountHeader({ account }: { account: Account }) {
  return <div data-account={account} />;
}
${SENSITIVE}`),
    ).toEqual([]);
  });

  // Props in a server-only module never reach a browser; the Server->Client boundary is
  // detectServerClientLeak's (M9), and double-reporting it here would be the #1062 masking shape.
  it("stays silent in a module that imports server-only", () => {
    expect(
      run(`import "server-only";
export function AccountHeader({ account }: { account: Account }) {
  return <Avatar user={account} />;
}
${SENSITIVE}`),
    ).toEqual([]);
  });

  // A BOUND, tested so it is a measured limit rather than an unstated one: the type must be
  // declared in the same file. If this case ever starts firing, the rule gained cross-file type
  // resolution and the scope sentence in its impact text is stale.
  it("does not resolve an imported type — the same-file bound, stated in the finding's impact", () => {
    expect(
      run(`import type { Account } from "./types";
export function AccountHeader({ account }: { account: Account }) {
  return <Avatar user={account} />;
}
`),
    ).toEqual([]);
  });
});
