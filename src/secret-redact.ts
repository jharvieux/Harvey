const SECRET_PATTERNS: readonly RegExp[] = [
  /gh[pousr]_[A-Za-z0-9]{16,}/g,
  /github_pat_[A-Za-z0-9_]{20,}/g,
  /sk-[A-Za-z0-9]{16,}/g,
  /AKIA[0-9A-Z]{16}/g,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
];

function addSecretVariant(values: Set<string>, value: string): void {
  // Provider credentials are materially longer than this. Ignoring shorter test placeholders
  // prevents a one-character token (for example "t") from corrupting every matching character in
  // otherwise valid tracker response fields while the complete Authorization value stays covered.
  if (value.length < 8) return;
  values.add(value);
  values.add(encodeURIComponent(value));
  values.add(Buffer.from(value, "utf8").toString("base64"));
  values.add(Buffer.from(value, "utf8").toString("base64url"));
}

export function credentialSecretsFromHeaders(headers: Readonly<Record<string, string>>): string[] {
  const values = new Set<string>();
  for (const [name, value] of Object.entries(headers)) {
    if (!/(?:authorization|token|api[_-]?key|secret|password|cookie)/i.test(name)) continue;
    addSecretVariant(values, value);
    const scheme = value.match(/^(?:Basic|Bearer)\s+(.+)$/i);
    if (scheme?.[1]) addSecretVariant(values, scheme[1]);
    if (/^Basic\s+/i.test(value) && scheme?.[1]) {
      try {
        const decoded = Buffer.from(scheme[1], "base64").toString("utf8");
        addSecretVariant(values, decoded);
        const separator = decoded.indexOf(":");
        if (separator >= 0) addSecretVariant(values, decoded.slice(separator + 1));
      } catch {
        // A malformed Basic value is still covered by the exact header-value variants above.
      }
    }
  }
  return [...values].filter(Boolean).sort((a, b) => b.length - a.length);
}

export function redactConfiguredSecrets(text: string, configuredSecrets: readonly string[]): string {
  let out = text;
  for (const secret of [...new Set(configuredSecrets)].filter(Boolean).sort((a, b) => b.length - a.length)) {
    out = out.split(secret).join("[REDACTED]");
  }
  return out;
}

export function redactSecrets(text: string, configuredSecrets: readonly string[] = []): string {
  let out = redactConfiguredSecrets(text, configuredSecrets)
    .replace(/(https?:\/\/)[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(/(https?:\/\/[^\s?#]+)[?#][^\s]*/gi, "$1?[REDACTED]");
  for (const pattern of SECRET_PATTERNS) out = out.replace(pattern, "[REDACTED]");
  return out.replace(/(bearer|token|api[_-]?key|password|secret)(["'\s:=]+)([A-Za-z0-9._\-/+]{8,})/gi, "$1$2[REDACTED]");
}

export function redactJsonStrings(value: unknown, configuredSecrets: readonly string[]): unknown {
  if (typeof value === "string") return redactConfiguredSecrets(value, configuredSecrets);
  if (Array.isArray(value)) return value.map((entry) => redactJsonStrings(entry, configuredSecrets));
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, redactJsonStrings(entry, configuredSecrets)]));
}

interface BoundedLineRedactor {
  write(chunk: string): void;
  end(): void;
}

export function createBoundedLineRedactor(options: {
  write: (redacted: string) => void;
  maxLineChars?: number;
  onRedacted?: (redacted: string) => void;
}): BoundedLineRedactor {
  const maxLineChars = options.maxLineChars ?? 64 * 1024;
  if (!Number.isSafeInteger(maxLineChars) || maxLineChars < 1) throw new Error("maxLineChars must be a positive safe integer");
  let buffered = "";
  let discardingLongLine = false;

  const emit = (value: string): void => {
    options.write(value);
    options.onRedacted?.(value);
  };
  const suppressLongLine = (): void => {
    emit(`[diagnostic line exceeded ${maxLineChars} characters; content suppressed]\n`);
  };

  return {
    write(chunk: string): void {
      let offset = 0;
      while (offset < chunk.length) {
        const newline = chunk.indexOf("\n", offset);
        const end = newline === -1 ? chunk.length : newline;
        const segment = chunk.slice(offset, end);
        if (!discardingLongLine) {
          if (buffered.length + segment.length > maxLineChars) {
            buffered = "";
            discardingLongLine = true;
            suppressLongLine();
          } else {
            buffered += segment;
          }
        }
        if (newline === -1) return;
        if (!discardingLongLine) emit(redactSecrets(`${buffered}\n`));
        buffered = "";
        discardingLongLine = false;
        offset = newline + 1;
      }
    },
    end(): void {
      if (buffered) emit(redactSecrets(buffered));
      buffered = "";
      discardingLongLine = false;
    },
  };
}
