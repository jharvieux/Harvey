import OpenAI from "openai";

// PLANTED BUG (P-DANGEROUSLY-ALLOW-BROWSER, #565): the canonical no-code "the AI key is in the
// bundle" footgun. The SDK requires dangerouslyAllowBrowser: true to run client-side precisely
// because doing so exposes the API key to every visitor (it is inlined into the bundle alongside the
// VITE_ env). harvey-dangerously-allow-browser → high. This is nocode-rescue #2 (browser LLM key).
export const ai = new OpenAI({
  apiKey: import.meta.env.VITE_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});
