import OpenAI from "openai";

// TRUE NEGATIVE (N-OPENAI-SERVER, #565): the LLM client is constructed server-side with the key read
// from a server-only env and NO dangerouslyAllowBrowser flag — the key never reaches the browser.
// harvey-dangerously-allow-browser matches only the `dangerouslyAllowBrowser: true` literal, so this
// must clear.
export const ai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});
