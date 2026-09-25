// Minimal Markdown + YAML-frontmatter reader/writer for draft files (design §4.2). This is NOT a
// general YAML parser — it handles exactly the shapes the builder writes into its own drafts:
// scalar strings/numbers/booleans, an inline string array (`dependsOn: [a, b]`), and a single
// level of nesting for the `published:` block. Builder drafts reject unsupported structure;
// quoted scalars use JSON escapes so generated strings round-trip without introducing fields.

export type FrontmatterValue = string | number | boolean | string[] | Record<string, string>;
export type FrontmatterData = Record<string, FrontmatterValue>;

export interface ParsedDoc {
  data: FrontmatterData;
  body: string;
}

const FENCE = "---";

export function parseFrontmatter(
  raw: string,
  options: { /** Builder-owned drafts require frontmatter; templates and imported Markdown may omit it. */ required?: boolean } = {},
): ParsedDoc {
  const normalized = raw.replace(/\r\n/g, "\n");
  const lines = normalized.split("\n");
  if (lines[0] !== FENCE) {
    if (options.required) throw new Error("frontmatter is required for builder drafts");
    return { data: {}, body: raw };
  }
  const end = lines.findIndex((line, index) => index > 0 && line === FENCE);
  if (end === -1) throw new Error("unterminated frontmatter block");
  return {
    data: parseBlock(lines.slice(1, end), options.required === true),
    body: lines.slice(end + 1).join("\n"),
  };
}

function parseBlock(lines: string[], strict: boolean): FrontmatterData {
  const data: FrontmatterData = {};
  let nestKey: string | null = null;
  const nestedKeys = new Map<string, Set<string>>();
  for (const line of lines) {
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
    const indented = /^\s/.test(line);
    const colon = line.indexOf(":");
    if (colon === -1) {
      if (strict) throw new Error(`malformed frontmatter line: ${line}`);
      continue;
    }
    const key = line.slice(0, colon).trim();
    const rawVal = line.slice(colon + 1).trim();
    if (key === "") throw new Error(`malformed frontmatter line: ${line}`);

    if (indented) {
      if (strict && !/^ {2}\S/.test(line)) throw new Error(`unsupported nested frontmatter indentation: ${key}`);
      if (!nestKey) {
        if (strict) throw new Error(`unexpected nested frontmatter field: ${key}`);
        continue;
      }
      const nested = data[nestKey];
      const seen = nestedKeys.get(nestKey)!;
      if (seen.has(key)) throw new Error(`duplicate frontmatter field: ${nestKey}.${key}`);
      seen.add(key);
      if (nested && typeof nested === "object" && !Array.isArray(nested)) nested[key] = parseString(rawVal, strict);
      continue;
    }
    if (Object.hasOwn(data, key)) throw new Error(`duplicate frontmatter field: ${key}`);
    if (rawVal === "") {
      data[key] = {};
      nestKey = key;
      nestedKeys.set(key, new Set());
      continue;
    }
    nestKey = null;
    data[key] = parseScalar(rawVal, strict);
  }
  return data;
}

function parseScalar(raw: string, strict: boolean): FrontmatterValue {
  if (raw.startsWith("[") || raw.endsWith("]")) {
    if (!(raw.startsWith("[") && raw.endsWith("]"))) {
      if (strict) throw new Error(`malformed frontmatter array: ${raw}`);
      return parseString(raw, false);
    }
    const inner = raw.slice(1, -1).trim();
    if (inner === "") return [];
    const values: string[] = [];
    let start = 0;
    let quote = "";
    for (let i = 0; i < inner.length; i++) {
      const char = inner[i]!;
      if (quote === '"' && char === "\\") { i++; continue; }
      if (quote === "'" && char === "'" && inner[i + 1] === "'") { i++; continue; }
      if (quote) { if (char === quote) quote = ""; continue; }
      if (char === '"' || char === "'") quote = char;
      else if (char === ",") { values.push(inner.slice(start, i).trim()); start = i + 1; }
      else if (strict && (char === "[" || char === "]" || char === "{" || char === "}")) throw new Error(`malformed frontmatter array: ${raw}`);
    }
    values.push(inner.slice(start).trim());
    if (strict && (quote || values.some((value) => value === ""))) throw new Error(`malformed frontmatter array: ${raw}`);
    return values.map((value) => parseString(value, strict));
  }
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (/^-?\d+(\.\d+)?$/.test(raw)) return Number(raw);
  return parseString(raw, strict);
}

function parseString(s: string, strict: boolean): string {
  if (s.startsWith('"')) {
    try {
      const parsed: unknown = JSON.parse(s);
      if (typeof parsed === "string") return parsed;
    } catch { /* A quoted scalar must be complete and have valid escapes. */ }
    if (strict) throw new Error(`unterminated or malformed frontmatter string: ${s}`);
  }
  if (s.startsWith("'")) {
    if (/^'(?:[^']|'')*'$/.test(s)) return s.slice(1, -1).replaceAll("''", "'");
    if (strict) throw new Error(`unterminated or malformed frontmatter string: ${s}`);
  }
  if (strict && (s.endsWith('"') || s.endsWith("'"))) throw new Error(`unterminated frontmatter string: ${s}`);
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
  if (/^[A-Za-z0-9][A-Za-z0-9 ._/-]*$/.test(value) && !/^(?:true|false|-?\d+(?:\.\d+)?)$/.test(value)) return value;
  return JSON.stringify(value);
}
