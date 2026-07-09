// PLANTED BUG (P-HARDCODED-KEY): a provider API secret hardcoded in source. The value is
// FAKE (valid-shape only). TruffleHog --only-verified will NOT verify a dead key, so this
// lands at review tier, not the free count — the honest outcome for an unverifiable match.
const key = "sk-ant-api03-FAKEcalibrationncfBAepfJBd0Kh8oOOL8dKLzdocJ2isAjIhKtJ0RlgLKOmxgJTeKdNnFRIBXuDL7DxtpYlSXpfKtHFAA";

export async function complete(prompt) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": key, "content-type": "application/json" },
    body: JSON.stringify({ model: "claude-3-haiku", messages: [{ role: "user", content: prompt }] }),
  });
  return res.json();
}
