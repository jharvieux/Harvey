// NEGATIVE (N-PG-RESJSON-BENIGN-TOKEN, #701): the object literal names a "token" field, but it
// is a public share-link token, not a credential — the class of field #701 explicitly calls
// out as needing to stay dark. Only compound, unambiguous names (refreshToken, apiKey, ...) are
// curated in; a bare "token" is deliberately excluded to avoid firing on ordinary DTOs.
export function getShareLink(req, res) {
  const id = req.params.id;
  res.json({ id, url: "https://app.example.com/s/abc", token: "share-link-abc123" });
}
