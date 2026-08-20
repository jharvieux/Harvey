import type { CorpusEntry } from "./types.js";

const ROOT = "m5-polyglot";

export const m5PolyglotQualityEntries: CorpusEntry[] = [
  { module: "M5", id: "M5-POLY-P-PYTHON", kind: "positive", cls: "Python exception handler with pass-only body", location: `${ROOT}/python-positive.py`, match: ["python empty/pass exception handler"], expectedTier: "review", note: "The except block contains only pass; the bounded Python rule emits a review-tier M5 finding." },
  { module: "M5", id: "M5-POLY-N-PYTHON", kind: "negative", cls: "Python exception is wrapped and re-raised", location: `${ROOT}/python-negative.py`, note: "The paired handler raises a typed failure with the original cause instead of silently continuing." },
  { module: "M5", id: "M5-POLY-P-GO", kind: "positive", cls: "Go library package calls panic", location: `${ROOT}/library-positive.go`, match: ["go library panic"], expectedTier: "review", note: "A non-main package uses panic for a recoverable input error; the source-only rule emits M5 review evidence." },
  { module: "M5", id: "M5-POLY-N-GO", kind: "negative", cls: "Go application boundary terminates on fatal configuration", location: `${ROOT}/main-negative.go`, note: "The paired panic is in package main, an application boundary outside the bounded library-panic rule." },
  { module: "M5", id: "M5-POLY-P-RUST", kind: "positive", cls: "Rust production branch retains a todo macro", location: `${ROOT}/rust-positive.rs`, match: ["rust production stub"], expectedTier: "review", note: "The fallback match arm contains todo!, a deterministic panic when production reaches the branch." },
  { module: "M5", id: "M5-POLY-N-RUST", kind: "negative", cls: "Rust production branch returns a typed error", location: `${ROOT}/rust-negative.rs`, note: "The paired fallback returns Result::Err and contains no todo!, unimplemented!, or unsafe unwrap." },
  { module: "M5", id: "M5-POLY-DISCLOSE-CSHARP", kind: "positive", cls: "C# population receives an explicit NotAssessed source-coverage row", location: "(repo-wide)", match: ["source coverage not-assessed: csharp"], expectedTier: "review", note: "The C# file is identified but no C# classifier claims it; the rendered source tier receives a counted NotAssessed row." },
  { module: "M6", id: "M6-POLY-DISCLOSE-PYTHON", kind: "positive", cls: "Python population receives an explicit M6 NotAssessed row", location: "(repo-wide)", match: ["m6 source coverage not-assessed: python"], expectedTier: "review", note: "M6 currently examines JavaScript/TypeScript only; every identified Python source is counted and disclosed without clean credit." },
];
