// N-OWASP-REACT-PROP-SHAPED (NEGATIVE — must NOT be flagged, #1252): the sheet's own remedy for
// oversharing-props.tsx. Same account type, same Avatar, and the ONLY difference is that the two
// fields Avatar renders are projected out before they cross the component boundary — so the SSN and
// the session token never enter the Fiber tree.

import { Avatar } from "./avatar";

export function AccountHeaderShaped({ account }: { account: ShapedAccount }) {
  const { name, avatarUrl } = account;
  return <Avatar name={name} avatarUrl={avatarUrl} />;
}

interface ShapedAccount {
  name: string;
  avatarUrl: string;
  ssn: string;
  sessionToken: string;
}
