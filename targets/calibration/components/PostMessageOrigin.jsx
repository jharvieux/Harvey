// TRUE NEGATIVE (N-POSTMESSAGE-ORIGIN-OK): the same broadcast, but pinned to an explicit target
// origin so only the intended host can receive it. harvey-postmessage-wildcard matches only the
// literal "*" targetOrigin — cleared.
export function SsoBridge({ session }) {
  function send() {
    window.parent.postMessage(session, "https://app.example.com");
  }
  return <button onClick={send}>Sync session</button>;
}
