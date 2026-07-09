import { useState } from "react";

// N-SECRET-NAME (NEGATIVE — must NOT be flagged): variables NAMED like credentials that
// hold no secret value. Name-only "hardcoded credential" detectors (e.g. Sonar S2068) FP here;
// Harvey requires the value to match a provider key pattern or verify before flagging.
export default function ResetForm() {
  const passwordLabel = "Enter your new password";
  const secretQuestion = "What was your first pet's name?";
  const [awaitingPasswordReset, setAwaitingPasswordReset] = useState(false);

  return (
    <form onSubmit={() => setAwaitingPasswordReset(true)}>
      <label>{passwordLabel}</label>
      <input type="password" aria-label={passwordLabel} />
      <p>{secretQuestion}</p>
      {awaitingPasswordReset && <span>Check your email.</span>}
    </form>
  );
}
