// Minimal Markdown + YAML-frontmatter reader/writer for draft files (design §4.2). This is NOT a
// general YAML parser — it handles exactly the shapes the builder writes into its own drafts:
// scalar strings/numbers/booleans, an inline string array (`dependsOn: [a, b]`), and a single
// level of nesting for the `published:` block. Anything else in the frontmatter round-trips as a
// raw scalar string, which is enough because the builder owns this frontmatter.

export type FrontmatterValue = string | number | boolean | string[] | Record<string, string>;
export type FrontmatterData = Record<string, FrontmatterValue>;

export interface ParsedDoc {
  data: FrontmatterData;
  body: string;
}

const FENCE = "---";

export function parseFrontmatter(raw: string): ParsedDoc {
  const normalized = raw.replace(/\r\n/g, "\n");
  if (!normalized.startsWith(`${FENCE}\n`)) return { data: {}, body: raw };
  const end = normalized.indexOf(`\n${FENCE}`, FENCE.length + 1);
  if (end === -1) return { data: {}, body: raw };

  const block = normalized.slice(FENCE.length + 1, end);
  const body = normalized.slice(end + 1 + FENCE.length + 1); // skip "\n---\n"
  return { data: parseBlock(block), body };
}

function parseBlock(block: string): FrontmatterData {
  const data: FrontmatterData = {};
  let nestKey: string | null = null;
  for (const line of block.split("\n")) {
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
    const indented = /^\s/.test(line);
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const key = line.slice(0, colon).trim();
    const rawVal = line.slice(colon + 1).trim();

    if (indented && nestKey) {
      const nested = data[nestKey];
      if (nested && typeof nested === "object" && !Array.isArray(nested)) nested[key] = unquote(rawVal);
      continue;
    }
    if (rawVal === "") {
      data[key] = {};
      nestKey = key;
      continue;
    }
    nestKey = null;
    data[key] = parseScalar(rawVal);
  }
  return data;
}

function parseScalar(raw: string): FrontmatterValue {
  if (raw.startsWith("[") && raw.endsWith("]")) {
    const inner = raw.slice(1, -1).trim();
    if (inner === "") return [];
    return inner.split(",").map((s) => unquote(s.trim()));
  }
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (/^-?\d+(\.\d+)?$/.test(raw)) return Number(raw);
  return unquote(raw);
}

function unquote(s: string): string {
  if (s.length >= 2 && ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'")))) {
    return s.slice(1, -1);
  }
  return s;
}

export function serializeFrontmatter(data: FrontmatterData, body: string): string {
  const lines: string[] = [FENCE];
  for (const [key, value] of Object.entries(data)) {
    if (Array.isArray(value)) {
      lines.push(`${key}: [${value.map(quoteIfNeeded).join(", ")}]`);
    } else if (value !== null && typeof value === "object") {
      lines.push(`${key}:`);
      for (const [k, v] of Object.entries(value)) lines.push(`  ${k}: ${quoteIfNeeded(v)}`);
    } else if (typeof value === "string") {
      lines.push(`${key}: ${quoteIfNeeded(value)}`);
    } else {
      lines.push(`${key}: ${String(value)}`);
    }
  }
  lines.push(FENCE);
  return `${lines.join("\n")}\n${body}`;
}

function quoteIfNeeded(value: string): string {
  if (value === "") return '""';
  if (/^[A-Za-z0-9][A-Za-z0-9 ._/-]*$/.test(value) && !/^\d+$/.test(value)) return value;
  return `"${value.replace(/"/g, '\\"')}"`;
}
