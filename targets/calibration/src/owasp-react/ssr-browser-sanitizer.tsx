// OWASP React Security CS (draft), SSR Security: "Use a Server-Compatible Sanitization Library for
// SSR HTML". DOMPurify needs a browser DOM; imported into a Server Component it either throws or —
// with a permissive build — returns the input untouched, so the sanitizer call reads as protection
// while the raw CMS HTML is what actually renders, before hydration and before any client guard.

import DOMPurify from "dompurify";
import sanitizeHtml from "sanitize-html";

import { cms } from "../db/client";

export async function ArticleBody({ slug }: { slug: string }) {
  const article = await cms.getArticle(slug);
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(article.body) }} />;
}

export async function ArticleBodyServerSafe({ slug }: { slug: string }) {
  const article = await cms.getArticle(slug);
  return <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(article.body) }} />;
}
