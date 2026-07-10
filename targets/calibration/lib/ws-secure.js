// N-WSS-SECURE (NEGATIVE — must NOT be flagged): a WebSocket over TLS (`wss://`) — encrypted and
// integrity-protected. harvey-insecure-ws-url is anchored to the `ws://` scheme; the extra `s` of
// `wss://` does not match.
export function connectLiveFeed() {
  return new WebSocket("wss://feed.internal.example.com/stream");
}
