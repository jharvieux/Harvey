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
    return inner.split(",").map((s) => parseString(s.trim(), strict));
  }
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (/^-?\d+(\.\d+)?$/.test(raw)) return Number(raw);
  return parseString(raw, strict);
}

function parseString(s: string, strict: boolean): string {
  const doubleQuoted = s.startsWith('"') || s.endsWith('"');
  const singleQuoted = s.startsWith("'") || s.endsWith("'");
  if (strict && ((doubleQuoted && !(s.startsWith('"') && s.endsWith('"')))
      || (singleQuoted && !(s.startsWith("'") && s.endsWith("'"))))) {
    throw new Error(`unterminated frontmatter string: ${s}`);
  }
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
