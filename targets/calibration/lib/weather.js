// PLANTED BUG (P-SECRET-IN-URL): an API key passed as a URL query parameter. Secrets in the URL
// leak into access logs, proxy caches, browser history, and Referer headers. Semgrep
// harvey-secret-in-url-param matches the `?api_key=`/`&access_token=` interpolation → review.
export async function getForecast(apiKey, city) {
  return fetch(`https://api.weather.example.com/v1/forecast?city=${city}&api_key=${apiKey}`);
}

// NEGATIVE (N-SECRET-IN-HEADER): the same secret sent in an Authorization header, the correct
// transport — no secret-bearing query parameter, so the rule does not match. Cleared.
export async function getForecastSafe(apiKey, city) {
  return fetch(`https://api.weather.example.com/v1/forecast?city=${city}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
}
