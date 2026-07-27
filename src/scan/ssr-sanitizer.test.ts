import { describe, expect, it } from "vitest";
import { detectSsrSanitizerFindings } from "./ssr-sanitizer.js";

// #1239 — OWASP React Security CS (draft), SSR Security: "Use a Server-Compatible Sanitization
// Library for SSR HTML". The intent under test is the ASYMMETRY: `dompurify` is correct in the
// browser and inert on the server, so every test below pins which side of that line it is on.

const IMPORTS = `import DOMPurify from "dompurify";\n`;

describe("ssr-sanitizer (#1239 — browser-only sanitizer in a server-rendered module)", () => {
  it("flags DOMPurify.sanitize inside an async Server Component", () => {
    const text = `${IMPORTS}export async function ArticleBody({ slug }) {
  const article = await cms.getArticle(slug);
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(article.body) }} />;
}
`;
    const findings = detectSsrSanitizerFindings([{ path: "src/article.tsx", text }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "High", precisionTier: "high" });
    expect(findings[0]?.taxonomy).toBe("Browser-only sanitizer in a server-rendered component");
    expect(findings[0]?.evidence).toContain("async component");
  });

  it("flags the named `sanitize` export in a 'use server' module", () => {
    const text = `"use server";
import { sanitize } from "dompurify";
export async function renderComment(html) {
  return sanitize(html);
}
`;
    const findings = detectSsrSanitizerFindings([{ path: "src/actions.ts", text }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("'use server'");
  });

  it("flags an App Router page module even when the component is synchronous", () => {
    const text = `${IMPORTS}export default function Page({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}
`;
    expect(detectSsrSanitizerFindings([{ path: "app/blog/page.tsx", text }])).toHaveLength(1);
  });

  it("stays silent in a 'use client' module — DOMPurify's home", () => {
    const text = `'use client';
${IMPORTS}export default function Page({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}
`;
    expect(detectSsrSanitizerFindings([{ path: "app/blog/page.tsx", text }])).toHaveLength(0);
  });

  it("stays silent for isomorphic-dompurify and sanitize-html — the correct server forms", () => {
    const iso = `import DOMPurify from "isomorphic-dompurify";
export async function Body({ html }) { return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />; }
`;
    const shtml = `import sanitizeHtml from "sanitize-html";
export async function Body({ html }) { return <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(html) }} />; }
`;
    expect(detectSsrSanitizerFindings([{ path: "a.tsx", text: iso }, { path: "b.tsx", text: shtml }])).toHaveLength(0);
  });

  it("stays silent when the module supplies its own DOM — the documented server recipe", () => {
    const text = `import createDOMPurify from "dompurify";
import { JSDOM } from "jsdom";
const DOMPurify = createDOMPurify(new JSDOM("").window);
export async function Body({ html }) { return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />; }
`;
    expect(detectSsrSanitizerFindings([{ path: "src/body.tsx", text }])).toHaveLength(0);
  });

  it("stays silent in an ordinary (non-async, non-route) component — a Vite SPA emits no directive at all", () => {
    const text = `${IMPORTS}export function Bio({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}
`;
    expect(detectSsrSanitizerFindings([{ path: "src/components/Bio.tsx", text }])).toHaveLength(0);
  });

  it("flags only the dompurify call when a server-safe sibling sits in the same file", () => {
    const text = `${IMPORTS}import sanitizeHtml from "sanitize-html";
export async function Unsafe({ html }) { return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />; }
export async function Safe({ html }) { return <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(html) }} />; }
`;
    const findings = detectSsrSanitizerFindings([{ path: "src/both.tsx", text }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("Unsafe");
  });
});
