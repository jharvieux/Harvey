// Batch B4 — XSS & client-side sink family (#71, spec §"Batch 2 — XSS & client-side sink
// family"). Custom Semgrep taint rules (src/scan/rules/semgrep/xss.yml) scored against targets/
// calibration. Tiering follows the locked preamble: only ~100%-precision sinks are `high` (free
// count) — .innerHTML/insertAdjacentHTML and document.write, which execute markup/script
// unconditionally once the source is tainted. The heuristic sinks (href scheme, window.location
// assignment, setAttribute, a DB-read source reaching dangerouslySetInnerHTML) are `review`.
// XSS-via-tainted-dangerouslySetInnerHTML (P-XSS-DSIH) and its sanitized/constant lookalike
// (N-DSIH-SANITIZED) already ship in base.entries.ts; B4 does not duplicate them. See
// GROUND-TRUTH.md §B4.

import type { CorpusEntry } from "./types.js";

export const b4XssEntries: CorpusEntry[] = [
  // --- POSITIVES (must be caught) ---
  { id: "P-DOM-XSS-INNERHTML", kind: "positive", cls: "DOM XSS via .innerHTML", location: "Widget.jsx", match: ["innerhtml"], expectedTier: "high", note: "router.query.q assigned straight to ref.current.innerHTML in components/Widget.jsx. harvey-dom-innerhtml taint (router.query/location/searchParams → innerHTML/insertAdjacentHTML, sanitizer stop) → high." },
  { id: "P-DOM-XSS-DOCWRITE", kind: "positive", cls: "DOM XSS via document.write", location: "Embed.jsx", match: ["document-write"], expectedTier: "high", note: "location.hash (URL fragment) flows into document.write() in components/Embed.jsx. harvey-document-write taint → high." },
  { id: "P-XSS-STORED-DSIH", kind: "positive", cls: "Stored XSS — DB value into dangerouslySetInnerHTML", location: "comment.js", match: ["stored"], expectedTier: "review", note: "A Supabase select().single() result flows into __html with no sanitizer in pages/comment.js — stored XSS (persisted payload, not reflected). harvey-dangerously-set-inner-html-stored taint (supabase .from().select() → dangerouslySetInnerHTML) → review." },

  // #613 (vibe-dummy stage-06/10) — the prop/param-sourced dangerouslySetInnerHTML family. The stored
  // rule keys on a Supabase select and the reflected rule on request sources; neither matches HTML that
  // arrives as a component prop or function parameter, which is the common React shape.
  { id: "P-DSIH-PROP", kind: "positive", cls: "prop/param value into dangerouslySetInnerHTML, no sanitizer", location: "UserBioDangerous.tsx", match: ["inner-html-prop"], expectedTier: "review", note: "#613: components/UserBioDangerous.tsx renders <div dangerouslySetInnerHTML={{ __html: user.bio }} /> (a prop member) and __html: html (a bare param) with no sanitizer. harvey-dangerously-set-inner-html-prop matches any non-literal, non-sanitized $VAL (string literals — incl. propagated consts — and DOMPurify.sanitize/sanitizeHtml/sanitize/escapeHtml wraps excluded via metavariable-pattern) → review. The prop/param source facet neither the stored (DB) nor reflected (request) rule covered." },
  { id: "N-DSIH-PROP-ESCAPED", kind: "negative", cls: "prop escaped before __html + constant literal + plain text", location: "UserBioSafe.tsx", match: ["inner-html-prop"], note: "#613 stage-11 control: components/UserBioSafe.tsx wraps the prop in escapeHtml() before __html, renders a constant STATIC_HTML literal, and interpolates {user.bio} as plain JSX text. harvey-dangerously-set-inner-html-prop excludes sanitizer wraps and (via constant propagation) string-literal consts, and plain text is not a dangerouslySetInnerHTML sink at all — cleared. Also proves it stays dark on the existing pages/about.js STATIC_BIO/sanitizeHtml negative." },
  { id: "P-XSS-HREF-JS", kind: "positive", cls: "javascript: URL XSS via <a href>", location: "AnchorLink.jsx", match: ["href-js-url"], expectedTier: "review", note: "router.query.next flows into a native <a href> with no scheme allowlist in components/AnchorLink.jsx. harvey-href-js-url taint → review." },
  { id: "P-XSS-DANGEROUS-URL", kind: "positive", cls: "Open-URL sink via window.location assignment", location: "LocationNav.jsx", match: ["open-url-sink"], expectedTier: "review", note: "A URLSearchParams 'to' value is assigned directly to window.location in components/LocationNav.jsx. harvey-open-url-sink taint → review." },
  { id: "P-XSS-SETATTR", kind: "positive", cls: "javascript: URL XSS via setAttribute", location: "ImgAttr.jsx", match: ["set-attribute-xss"], expectedTier: "review", note: "router.query.avatar flows into ref.current.setAttribute('src', ...) in components/ImgAttr.jsx. harvey-set-attribute-xss taint → review." },

  // --- NEGATIVES (must NOT be flagged in the free count) ---
  { id: "N-INNERHTML-STATIC", kind: "negative", cls: "innerHTML assigned a constant literal", location: "WidgetSafe.jsx", note: "ref.current.innerHTML = '<strong>Loading…</strong>' in components/WidgetSafe.jsx — constant string, no tainted source. harvey-dom-innerhtml fires only on router.query/location/searchParams — cleared." },
  { id: "N-HREF-INTERNAL", kind: "negative", cls: "href from a constant internal route", location: "NavLink.jsx", note: "<Link href=\"/dashboard\"> in components/NavLink.jsx — next/link, constant string, not a native <a> and not request-derived. harvey-href-js-url fires only on a native <a href={...}> from a tainted source — cleared." },
  { id: "N-SEARCHPARAMS-TEXT", kind: "negative", cls: "searchParams value rendered as text", location: "search-results.js", note: "<p>Results for: {router.query.q}</p> in pages/search-results.js — React text child, auto-escaped, never an innerHTML/href/setAttribute/document.write sink. None of the B4 rules match a plain text expression — cleared." },
];
