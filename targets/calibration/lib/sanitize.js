// Minimal local HTML sanitizer stand-in so pages/about.js (N-DSIH-SANITIZED) is a
// self-contained, build-safe benign fixture. A real app would use DOMPurify.sanitize.
export function sanitizeHtml(html) {
  return String(html).replace(/<script[\s\S]*?<\/script>/gi, "").replace(/ on\w+="[^"]*"/gi, "");
}
