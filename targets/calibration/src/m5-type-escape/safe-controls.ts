interface Payload {
  id: string;
}

declare const raw: unknown;
declare const schema: { parse(value: unknown): unknown };
declare const legacySdk: unknown;
declare function assertPayload(value: unknown): asserts value is Payload;

// Schema-validated boundary: parse throws before the value can cross this boundary.
export const parsed = schema.parse(raw) as unknown as Payload;

assertPayload(raw);
// Validated boundary: checked by assertPayload immediately above.
export const narrowed = raw as unknown as Payload;

// Third-party interop: the legacy SDK omits this stable callback from its declarations.
export const legacyCallback = legacySdk as any;

// @ts-expect-error — the negative control intentionally proves the compiler rejects this shape.
export const expectedCompilerError: number = raw;

// @ts-ignore -- upstream SDK declaration is missing this documented field
export const explainedIgnore: number = raw;
