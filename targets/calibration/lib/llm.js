// PLANTED BUG (P-OPENAI-KEY): a hardcoded OpenAI API key. The VALUE is DEFANGED — the real
// sk-...T3BlbkFJ... shape trips GitHub push protection, so the committed literal is a pure
// high-entropy fake with the provider prefix removed. gitleaks catches it via generic-api-key
// (high-entropy value on a KEY-named var) at review; the provider-specific openai-api-key
// pattern was validated on the real-shape value pre-commit (see GROUND-TRUTH §B1). Review, not
// the free count — an unverifiable hardcoded key (same class/tier as P-HARDCODED-KEY).
const OPENAI_API_KEY = "Z9Qm2vXcW8rNpKdLhGfYsAe4Uo1Bx6Vt0Zi7Ny5Mw3Qr8Kp2";

export async function embed(text) {
  const res = await fetch("https://api.openai.com/v1/embeddings", {
    method: "POST",
    headers: { authorization: `Bearer ${OPENAI_API_KEY}`, "content-type": "application/json" },
    body: JSON.stringify({ model: "text-embedding-3-small", input: text }),
  });
  return res.json();
}
