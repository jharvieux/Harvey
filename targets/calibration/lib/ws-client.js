// PLANTED BUG (P-INSECURE-WS-URL): a WebSocket opened over the plaintext `ws://` scheme — the
// session token in the connection and every message travel unencrypted, open to interception and
// tampering by any on-path attacker. Use `wss://` (TLS). harvey-insecure-ws-url matches a WebSocket
// constructed with a `ws://` string literal.
export function connectLiveFeed() {
  return new WebSocket("ws://feed.internal.example.com/stream");
}
