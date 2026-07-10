// PLANTED BUG (P-POSTMESSAGE-WILDCARD): the session payload is broadcast to the parent frame with
// targetOrigin '*', so any site that framed this page receives it. Pin the target origin to the
// exact expected host. Semgrep harvey-postmessage-wildcard (literal "*" targetOrigin) → high.
export function SsoBridge({ session }) {
  function send() {
    window.parent.postMessage(session, "*");
  }
  return <button onClick={send}>Sync session</button>;
}
