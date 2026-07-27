// OWASP React Security CS (draft), Sensitive Data Exposure: "Minimize Sensitive Data in Component
// State and Props". Avatar needs a name and a photo; handing it the whole account object puts the
// SSN and the session token into React's Fiber tree, which session-recording scripts and browser
// extensions can read even though neither field is ever rendered.

import { Avatar } from "./avatar";

export function AccountHeader({ account }: { account: Account }) {
  return <Avatar user={account} />;
}

export function AccountHeaderShaped({ account }: { account: Account }) {
  const { name, avatarUrl } = account;
  return <Avatar name={name} avatarUrl={avatarUrl} />;
}

interface Account {
  name: string;
  avatarUrl: string;
  ssn: string;
  sessionToken: string;
}
