// OWASP React Security CS (draft), Sensitive Data Exposure: "Minimize Sensitive Data in Component
// State and Props". Avatar needs a name and a photo; handing it the whole account object puts the
// SSN and the session token into React's Fiber tree, which session-recording scripts and browser
// extensions can read even though neither field is ever rendered.
//
// #1252 moved the SHAPED variant out to oversharing-props-shaped.tsx. While it lived here the
// positive's own finding satisfied that row's relevance check, so it could only ever score
// trivially — the same correction #1237 and #1238 made to their negatives in this directory.

import { Avatar } from "./avatar";

export function AccountHeader({ account }: { account: Account }) {
  return <Avatar user={account} />;
}

interface Account {
  name: string;
  avatarUrl: string;
  ssn: string;
  sessionToken: string;
}
