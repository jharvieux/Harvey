const translations = {
  en: { hello: "Hello" },
  fr: { hello: "Bonjour" },
  es: { hello: "Hola" },
};

const LOCALES = ["en", "fr", "es"];

// N-OBJ-INJECTION (NEGATIVE — must NOT be flagged): bracket access on a validated,
// enum-constrained key. eslint-plugin-security detect-object-injection flags any obj[expr];
// this is safe because `locale` is checked against a known allowlist first.
export function t(locale, key) {
  const safe = LOCALES.includes(locale) ? locale : "en";
  return translations[safe][key];
}
