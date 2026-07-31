// N-OWASP-REACT-PROP-BENIGN-OBJECT (NEGATIVE — must NOT be flagged, #1252): the harder negative,
// and the one that tests the conjunct the shaped twin cannot. This DOES hand a whole domain object
// to a component as one prop — the syntactic half of the rule is fully satisfied — and it is
// correct code, because nothing in the type is sensitive. If the rule ever fires here it has
// stopped reading the type and become "any object passed as a prop", which on a real repo is
// hundreds of rows.

import { Avatar } from "./avatar";

export function ProfileHeader({ profile }: { profile: PublicProfile }) {
  return <Avatar user={profile} />;
}

interface PublicProfile {
  name: string;
  avatarUrl: string;
  headline: string;
  email: string;
}
