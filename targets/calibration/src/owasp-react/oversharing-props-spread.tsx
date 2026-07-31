// P-OWASP-REACT-PROP-OVERSHARE-SPREAD (POSITIVE — must STILL fire, #1252): the same overshare
// spelled as a JSX spread instead of a named prop. `{...account}` is the shape a developer reaches
// for when the child's props happen to line up with the object's fields, and it puts every field
// into the child's props individually — strictly worse than the named form, and invisible to a rule
// that only reads `prop={obj}`.

import { Avatar } from "./avatar";

export function AccountHeaderSpread({ account }: { account: SpreadAccount }) {
  return <Avatar {...account} />;
}

interface SpreadAccount {
  name: string;
  avatarUrl: string;
  passwordHash: string;
}
