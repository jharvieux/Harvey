# Model Routing — Cost-Tiered LLM Strategy

Status: v1 (all pricing/model data researched 2026-07-01) · Issue: #19
Consumed by: `architecture.md` (the `ModelRouter` component), `epic-builder.md` §7, `fix-implementation.md` §5.

**Research date: 2026-07-01.** All prices are USD per 1M tokens, observed on official pricing pages on this date unless noted. Model generations have shifted substantially in 2026: DeepSeek is now on **V4** (V3.x/R1 deprecated), Zhipu/Z.ai is on **GLM-5.2**, Qwen is on **Qwen3.7**, Anthropic's line is **Haiku 4.5 / Sonnet 5 / Opus 4.8 / Fable 5**, OpenAI is on **GPT-5.4/5.5**, Google on **Gemini 3.x**. Re-verify before implementation — this market moves monthly.

---

## 1. Low-cost tier

### 1.1 DeepSeek (first-party API)

DeepSeek released the **V4 family on 2026-04-24** (open weights, MIT). The legacy `deepseek-chat` / `deepseek-reasoner` names now alias `deepseek-v4-flash` (non-thinking / thinking) and **are deprecated 2026-07-24**. R1-style reasoning is absorbed into V4's "thinking" mode — there is no separate reasoner model anymore.

| | deepseek-v4-flash | deepseek-v4-pro |
|---|---|---|
| Architecture | 284B MoE / 13B active | 1.6T MoE / 49B active |
| Input (cache miss) | **$0.14** | **$0.435** |
| Input (cache hit) | $0.0028 | $0.003625 |
| Output | **$0.28** | **$0.87** |
| Context / max out | 1M / 384K | 1M / 384K |
| Tool use / JSON | Yes / Yes (structured output; FIM & prefix-completion betas) | Yes / Yes |
| Modes | Thinking + non-thinking | Thinking + non-thinking |

- **Coding reputation (V4-Pro, thinking):** SWE-bench Verified **80.6**, LiveCodeBench **93.5** (reported #1 of 118 models), Codeforces 3206, Terminal-Bench 2.0 67.9. Weak spot: SWE-bench Pro **55.4** (long-horizon agentic work trails GLM-5.1/Kimi). Caveat: US CAISI held-out evals place it below its public-benchmark headlines, suggesting some benchmark overfitting. V4-Flash has no published per-benchmark scores (vendor: "close to V4-Pro on simple agent tasks").
- The old off-peak discount program is gone; no time-window discounts currently listed.
- **Privacy caveat: first-party API is unsuitable for client code — see §4.**

Sources: [DeepSeek pricing](https://api-docs.deepseek.com/quick_start/pricing) · [V4 release note](https://api-docs.deepseek.com/news/news260424) · [Artificial Analysis: V4-Pro](https://artificialanalysis.ai/models/deepseek-v4-pro) · [benchmark review](https://blog.4sapi.com/blog/deepseek-v4-pro-benchmark-review-strengths-weaknesses)

### 1.2 Z.ai / Zhipu GLM

Current flagship is **GLM-5.2** (June 2026, open-weight MIT, 1M context). GLM-4.x remains served as a cheap tier.

| Model | Input | Cached in | Output | Context |
|---|---|---|---|---|
| GLM-5.2 (flagship) | $1.40 | $0.26 | $4.40 | 1M / 128K out |
| GLM-5 | $1.00 | $0.20 | $3.20 | 200K |
| GLM-4.7 / 4.6 / 4.5 | $0.60 | $0.11 | $2.20 | 200K (4.6) |
| GLM-4.5-Air | $0.20 | $0.03 | $1.10 | 128K |
| GLM-4.7-FlashX | $0.07 | $0.01 | $0.40 | — |
| GLM-4.7-Flash / 4.5-Flash | Free | — | Free | — |

- **Capabilities:** OpenAI-compatible API; function calling, MCP, structured JSON output, context caching, thinking mode with `reasoning_effort`.
- **Coding reputation:** GLM-5.2 scores **SWE-bench Pro 62.1** and Terminal-Bench 2.1 **81.0** — widely reported as the top open-weight coding model ([Tom's Hardware, June 2026](https://www.tomshardware.com/tech-industry/artificial-intelligence/z-ai-free-glm-5-2-tops-the-open-weight-ai-rankings-on-all-huawei-silicon)). Vendor tool-call-reliability claims are not independently verified.
- **GLM Coding Plan** (subscription, for interactive agents like Claude Code — *not* usable for backend API automation per ToS): Lite $18/mo (~80 prompts/5h), Pro $72/mo (~400), Max $160/mo (~1,600); ~30% promo through ~Sept 2026. GLM-5.2 burns 2–3x quota multipliers.

Sources: [Z.ai pricing](https://docs.z.ai/guides/overview/pricing) · [Coding Plan](https://docs.z.ai/devpack/overview) · [GLM-5.2 docs](https://docs.z.ai/guides/llm/glm-5.2)

### 1.3 Alibaba Qwen (Model Studio international/Singapore)

| Model | Input | Output | Notes |
|---|---|---|---|
| Qwen3.7-Max (flagship) | $2.50 | $7.50 | 1M ctx; ~50% launch promo in console; SWE-bench Pro ~60.6 |
| Qwen3.7-Plus | $0.40 (≤256K) / $1.20 (>256K) | $1.60 / $4.80 | 1M ctx; vision + agentic tool invocation |
| Qwen3-Coder-Plus | $1.00–$6.00 tiered | $5.00–$60.00 | 1M ctx; expensive at long context |
| Qwen3-Coder-Flash | $0.30–$1.60 tiered | $1.50–$9.60 | 1M ctx |
| Qwen-Flash | $0.05 | $0.40 | budget floor |

- Tool use + JSON mode supported (OpenAI-compatible). Qwen3.7 weights **not yet open** as of June 2026. Free tier ended 2026-04-15; mainland endpoint is 60–70% cheaper but PRC-hosted. Tiered long-context pricing makes Coder models deceptively costly on big repos.

Sources: [Alibaba Model Studio pricing](https://www.alibabacloud.com/help/en/model-studio/model-pricing) · [Qwen3.7-Plus launch](https://www.marktechpost.com/2026/06/02/alibabas-qwen-team-launches-qwen3-7-plus-adding-vision-deep-reasoning-tool-invocation-and-autonomous-iteration-on-the-bailian-platform/)

### 1.4 Other budget contenders

| Model | Input / Output | Context | One-liner |
|---|---|---|---|
| Moonshot Kimi K2.7 Code | $0.95 / $4.00 ($0.19 cache-hit) | 256K | Strongest Kimi coder ([pricing](https://platform.kimi.ai/docs/pricing/chat-k27-code)) |
| MiniMax M2.7 | ~$0.30 / $1.20 | ~205K | Cheapest capable agentic model |
| Mistral Devstral Medium | $0.40 / $2.00 | — | EU alternative; Devstral Small ~$0.07–0.10/$0.28–0.30; 50% batch discount ([pricing](https://mistral.ai/pricing/)) |

**Value picks:** DeepSeek-V4-Flash ($0.14/$0.28) and GLM-4.5-Air ($0.20/$1.10) for bulk work; GLM-5.2 is the strongest open-weight coder but is now mid-tier priced ($1.40/$4.40).

---

## 2. Mid tier (observed 2026-07-01)

| Model | ID | Input | Output | Context | Tool use / JSON | Coding reputation |
|---|---|---|---|---|---|---|
| **Claude Haiku 4.5** | `claude-haiku-4-5` | $1.00 (cache read ~0.1x) | $5.00 | 200K / 64K out | Full (tools + strict structured output) | SWE-bench Verified **73.3%** — best-in-class at the price ([Anthropic](https://www.anthropic.com/news/claude-haiku-4-5)) |
| **Gemini 3 Flash Preview** | `gemini-3-flash-preview` | $0.50 (cached $0.05) | $3.00 incl. thinking | 1M-class | Full (function calling + `responseSchema`) | Strong/fast; batch $0.25/$1.50 |
| **Gemini 3.5 Flash** (2026-05-19) | `gemini-3.5-flash` | $1.50 (cached $0.15) | $9.00 incl. thinking | 1M / ~64K out | Full | SWE-bench Verified **78.8%** (vals.ai), ~289 tok/s; notably pricier than 3-Flash |
| **GPT-5.4 mini** | `gpt-5.4-mini` | $0.75 (cached $0.075) | $4.50 | 400K-class | Full (strict `json_schema`) | Solid workhorse; `gpt-5.4-nano`: $0.20/$1.25 |

All four offer 50% batch discounts. Sources: [Gemini pricing](https://ai.google.dev/gemini-api/docs/pricing) · [OpenAI pricing](https://developers.openai.com/api/docs/pricing).

---

## 3. Flagship tier (observed 2026-07-01; brief)

| Model | ID | Input | Output | Context | SWE-bench Verified / Pro |
|---|---|---|---|---|---|
| **Claude Sonnet 5** (rel. 2026-06-30) | `claude-sonnet-5` | $3.00 (**intro $2.00 thru 2026-08-31**) | $15.00 (**intro $10.00**) | 1M / 128K out, no long-ctx premium | 85.2 / 63.2 |
| **Claude Opus 4.8** | `claude-opus-4-8` | $5.00 | $25.00 | 1M / 128K out, flat pricing | 88.6 / 69.2 |
| **Claude Fable 5** | `claude-fable-5` | $10.00 | $50.00 | 1M / 128K out | ~95 / 80.3 |
| **GPT-5.5** | `gpt-5.5` | $5.00 (cached $0.50); $10.00 long-ctx | $30.00; $45.00 long-ctx | Tiered short/long | ~88.7 vendor (~82 independent) / 58.6 |
| **Gemini 3.1 Pro Preview** | `gemini-3.1-pro-preview` | $2.00 ≤200K / $4.00 > | $12.00 ≤200K / $18.00 > | 1M, 200K price break | 80.6 / 54.2 |

- All support parallel function calling and strict structured outputs.
- **Fable 5 caveats:** thinking always-on, no sampling params, and **requires 30-day data retention (ZDR unavailable)** — a real constraint for this business (§4).
- Price-performance standout: **Sonnet 5 at intro $2/$10** is near-Opus coding quality at near-Haiku economics; **Gemini 3.1 Pro** is the cheapest flagship input but trails on coding benchmarks.

Sources: [OpenAI pricing](https://developers.openai.com/api/docs/pricing) · [GPT-5.5 announcement](https://openai.com/index/introducing-gpt-5-5/) · [Gemini pricing](https://ai.google.dev/gemini-api/docs/pricing) · [SWE-bench Pro leaderboard](https://labs.scale.com/leaderboard/swe_bench_pro_public) · [swebench.com](https://www.swebench.com/)

---

## 4. Privacy / hosting (critical for confidential client code)

### 4.1 First-party Chinese APIs

| | DeepSeek platform | Z.ai (international) |
|---|---|---|
| Entity / jurisdiction | Hangzhou DeepSeek AI Co., **PRC**; policy states data is collected, processed and **stored in the PRC** | JINGSHENG HENGXING TECHNOLOGY PTE. LTD., **Singapore**; GPUs/DB relocated to Singapore |
| Trains on inputs | **Yes** ("to train and improve... machine learning models"), personal-data opt-out only | API: **No** — DPA states API content is not stored (real-time processing); consumer chat data *is* used for training |
| Retention | Indefinite ("as long as needed") | API content not stored per DPA |
| ZDR / enterprise | None | Effectively ZDR-by-DPA for API |
| Risk notes | PIPL + National Intelligence Law Art. 7 exposure; Italy Garante ban, Berlin DPA finding, US House Select Committee report, Wiz exposed-DB incident | Materially better terms, but Chinese parent (Zhipu) = residual jurisdiction/ownership risk; mainland bigmodel.cn platform is PRC-hosted and should not be used |

**Verdict:** DeepSeek first-party is disqualifying for client code. Z.ai international is contractually reasonable but many security-audit clients will reject any Chinese-parent processor — treat as opt-in at best.

### 4.2 Open-weight serving via US providers

**Licenses:** DeepSeek V3/R1/V4 weights are **MIT** (unrestricted commercial use; only R1-Distill-Llama variants inherit Llama licenses — [DeepSeek-R1 weights](https://huggingface.co/deepseek-ai/DeepSeek-R1)). GLM-4.5/4.6 (and the 5.x line) are **MIT** on Hugging Face ([GLM-4.6](https://huggingface.co/zai-org/GLM-4.6)). Fully private self-hosting is legally clean and is the gold-standard option for the most sensitive engagements.

Availability & pricing (observed 2026-07-01):

| Provider | DeepSeek weights served | GLM weights served | ZDR / privacy posture |
|---|---|---|---|
| **Fireworks AI** | V4-Pro $1.74/$3.48; V4-Flash $0.14/$0.28 (V3/R1 delisted from serverless; on-demand deploy possible) | GLM-5.2 $1.40/$4.40 (4.5/4.6 delisted) | **Zero-retention by default** — prompts in volatile memory only, opt-in logging; SOC 2 II, HIPAA ([pricing](https://docs.fireworks.ai/serverless/pricing)) |
| **Together AI** | V4-Pro $1.74/$3.48 (V3.x/R1 serverless retired) | GLM-5.1/5.2 $1.40/$4.40 (4.6 deprecated) | No storage by default + explicit org-level **ZDR toggle**; no training without opt-in ([pricing](https://www.together.ai/pricing)) |
| **DeepInfra** | **V3.2 $0.26/$0.38**; V4-Flash **$0.09/$0.18**; V4-Pro $1.30/$2.60 | **GLM-4.6 $0.43/$1.74** ($0.08 cached) | In-memory during inference, deleted after response; no training on API data; may log small samples for debugging; no residency statement — budget option, slightly weaker posture ([privacy](https://docs.deepinfra.com/account/data-privacy)) |
| **AWS Bedrock** | R1 $1.35/$5.40; V3.1 $0.58/$1.68; V3.2 $0.62/$1.85 (managed serverless; DeepSeek excluded from Batch tier) | GLM-5.x now listed (4.x never offered) | **Strongest contractual posture**: prompts/outputs not stored, never shared with model providers, never used for training; US region pinning ([Bedrock pricing](https://aws.amazon.com/bedrock/pricing/), [Bedrock DeepSeek](https://aws.amazon.com/bedrock/deepseek/)) |
| **Google Vertex AI** | R1-0528, V3.1, V3.1-Terminus, V3.2-Exp as MaaS; any weights self-deployable via Model Garden | GLM-5 MaaS $1.00/$3.20 (publisher `zaiorg`) | No training on customer data; **but default 24h caching + abuse-monitoring logging — ZDR requires deliberate project-level configuration** ([Vertex DeepSeek](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/maas/deepseek)) |

Key operational fact: US serverless hosts have largely **rotated off V3.x/R1 and GLM-4.x to the newer generations** — don't design around a deprecated endpoint. DeepInfra is the outlier still serving the old cheap generation; Bedrock keeps V3.x managed.

### 4.3 Anthropic / OpenAI enterprise terms (brief)

- **Anthropic API:** no training on API data by default; default operational retention 7 days, 30-day via DPA. **ZDR available by approval** per-organization. **Exception: Fable 5 (and Mythos 5) are "Covered Models" requiring 30-day retention — no ZDR**; workspace-level mixing lets you keep ZDR for other models. ([retention docs](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention), [ZDR](https://privacy.claude.com/en/articles/8956058))
- **OpenAI API:** no training on API data by default; ~30-day abuse-monitoring retention; **ZDR by prior approval** (eligible endpoints only; incompatible with extended prompt caching and background mode). Verify ZDR is actually active before sending client code. ([enterprise privacy](https://openai.com/enterprise-privacy/))

---

## 5. Tiered routing patterns (established practice)

| Pattern | Idea | Evidence |
|---|---|---|
| **Cheap-first cascade** (FrugalGPT) | Send to cheapest model; a scorer decides accept vs. escalate | Up to 98% cost reduction at GPT-4 parity ([arXiv:2305.05176](https://arxiv.org/abs/2305.05176)); Cascade Routing unifies route+cascade optimally ([arXiv:2410.10347](https://arxiv.org/abs/2410.10347)) |
| **Learned routers** | Classifier predicts difficulty, routes upfront | RouteLLM: ~95% of GPT-4 quality sending only 14–26% of queries to the strong model ([LMSYS](https://lmsys.org/blog/2024-07-01-routellm/)); LiteLLM/Portkey for self-hosted gateway routing |
| **LLM-as-judge verification** | Stronger model grades cheaper output | Production-proven, but known biases: position, verbosity, self-preference ([arXiv:2410.21819](https://arxiv.org/abs/2410.21819)). Mitigations: swap candidate order, **use a judge from a different model family**, atomic per-criterion rubrics, calibrate against a human-labeled slice |
| **Confidence-threshold escalation** | Accept above high threshold, escalate below low | Self-reported confidence is miscalibrated; logprobs better; **self-consistency (sample agreement) most reliable**; adaptive early-stopping cuts sampling cost ~80% ([arXiv:2508.06225](https://arxiv.org/html/2508.06225v1)) |
| **Cross-model disagreement** | 2–3 diverse cheap models; agreement → accept, disagreement → escalate | Semantic-agreement cascades matched 70B quality at ~40% cost ([arXiv:2509.21837](https://arxiv.org/abs/2509.21837)) |
| **Security-triage precedents** | Deterministic scanner detects → LLM triages → confidence-gated suppression | **Semgrep Assistant**: >95% FP-classification accuracy, 96% agreement with security researchers, ~60% of triage auto-handled ([blog](https://semgrep.dev/blog/2025/semgrep-is-confidently-handling-60-of-all-triage-for-users-without-reducing-coverage/)); GitHub Copilot Autofix tests every fix before display ([docs](https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/responsible-use-autofix-code-scanning)) |

Design lessons: (a) cascade, don't just route — the cheap model's actual output is a better signal than predicting difficulty; (b) only auto-suppress findings at *high* FP confidence, never auto-suppress high-severity; (c) keep a CI eval set (50–500 labeled findings) gating any routing-threshold change.

---

## 6. Recommended 3-tier assignment

**Privacy baseline first:** no client code ever goes to DeepSeek first-party or bigmodel.cn. Low-tier open-weight models run on **Fireworks (ZDR default)** or **AWS Bedrock** (strongest terms); **DeepInfra** as budget fallback where client contracts allow. Anthropic/OpenAI under ZDR agreements. **Fable 5 is excluded from any ZDR-bound engagement** (mandatory 30-day retention) — use it only where the client consents, or keep Opus 4.8 as the ceiling.

### Tier definitions

These are the `bulk` / `standard` / `flagship` tiers the `ModelRouter` interface exposes (see `architecture.md` §2.2):

| Tier | Primary | Backup / cross-check | Cost (in/out) |
|---|---|---|---|
| **bulk** (T1) | DeepSeek-V4-Flash on Fireworks ($0.14/$0.28) or DeepInfra ($0.09/$0.18) | GLM-4.5-Air via US host, or Gemini 3 Flash Preview ($0.50/$3.00) as non-Chinese-weights alternative | ~$0.10–0.50 / $0.20–3.00 |
| **standard** (T2) | Claude Haiku 4.5 ($1/$5, ZDR-eligible) | GLM-5.2 on Fireworks ($1.40/$4.40) — strongest open-weight coder; GPT-5.4-mini ($0.75/$4.50) | ~$1–1.50 / $4.50–5 |
| **flagship** (T3) | **Claude Sonnet 5** ($2/$10 intro thru 2026-08-31, then $3/$15) | Opus 4.8 ($5/$25) for the hardest calls; GPT-5.5 or Gemini 3.1 Pro as *different-family* judge | $2–5 / $10–25 |

### Workload assignments

| Workload | Tier | Model | Escalation trigger |
|---|---|---|---|
| **Bulk classification/triage of scan findings** | bulk | DeepSeek-V4-Flash (strict JSON schema, batch) | Schema-validation failure; self-consistency <2/3 across 3 samples; severity ≥ High (always escalate); category = auth/crypto/injection |
| **Dedup of findings** | bulk (mostly non-LLM) | Embeddings + hash clustering first; V4-Flash only for ambiguous pair adjudication | Cluster-confidence below threshold → standard second opinion; never auto-merge findings of different severity |
| **User-story drafting** | bulk→standard | V4-Flash draft; Haiku 4.5 polish | Judge rubric score < threshold; client-facing final text always gets one standard pass |
| **Code-fix generation** | standard | GLM-5.2 (US-hosted) or Haiku 4.5 | Fix fails compile/tests/re-scan (Copilot-Autofix pattern: verify every fix mechanically before showing) → retry once at standard, then Sonnet 5; multi-file or framework-level fixes go straight to flagship |
| **Security-finding verification** (TP/FP adjudication) | flagship | Sonnet 5 as verifier over bulk triage output | Cross-family disagreement check: if Sonnet 5 disagrees with the bulk verdict, or on Critical findings, run GPT-5.5 or Gemini 3.1 Pro as tiebreaker; unresolved 3-way disagreement → human review. Never auto-suppress a Critical/High as FP without flagship + human sign-off |
| **Final report QA** | flagship | Opus 4.8 (rubric-based judge: completeness, severity consistency, evidence quality) | Judge from a different family (GPT-5.5) samples 10–20% of reports for calibration drift; QA failure → regenerate section at flagship, second failure → human editor |

### Escalation policy (uniform)

1. **Mechanical gates first** (free): JSON schema validation, fix compiles/tests pass, citation-to-code-line resolves. Failure → one same-tier retry, then escalate.
2. **Confidence gate:** 3-sample self-consistency at bulk; accept ≥2/3 agreement + calibrated confidence above threshold; else escalate.
3. **Severity override:** Critical/High findings skip bulk acceptance entirely — bulk output is treated as a draft for flagship verification.
4. **Disagreement gate:** flagship verifier vs. bulk verdict conflict → different-family tiebreaker → human.
5. **Budget expectation:** with RouteLLM/Semgrep-like numbers (60–85% handled below flagship), expect roughly 70–80% of tokens at bulk, 15–20% at standard, 5–10% at flagship — an effective blended rate near $0.50–1.00/M input vs. $3–5/M if everything ran on Sonnet 5.

### Watch-items

- **Sonnet 5 intro pricing ends 2026-08-31** ($2/$10 → $3/$15); Anthropic's new tokenizer also emits ~30% more tokens than Sonnet 4.6 — re-run cost models on real traffic, not token counts from the old tokenizer.
- **DeepSeek legacy aliases die 2026-07-24**; US hosts are actively rotating old open weights out of serverless. Pin exact model IDs per provider and keep the bulk slot provider-agnostic (LiteLLM-style gateway or a thin in-house OpenAI-compatible client) so DeepInfra/Fireworks/Bedrock can be swapped without pipeline changes.

---

### Source index (all observed 2026-07-01)

**Pricing:** [DeepSeek](https://api-docs.deepseek.com/quick_start/pricing) · [Z.ai](https://docs.z.ai/guides/overview/pricing) · [Z.ai Coding Plan](https://docs.z.ai/devpack/overview) · [Alibaba Model Studio](https://www.alibabacloud.com/help/en/model-studio/model-pricing) · [Kimi](https://platform.kimi.ai/docs/pricing/chat-k27-code) · [Mistral](https://mistral.ai/pricing/) · [Gemini](https://ai.google.dev/gemini-api/docs/pricing) · [OpenAI](https://developers.openai.com/api/docs/pricing) · [Fireworks](https://docs.fireworks.ai/serverless/pricing) · [Together](https://www.together.ai/pricing) · [DeepInfra GLM-4.6](https://deepinfra.com/zai-org/GLM-4.6) · [AWS Bedrock pricing](https://aws.amazon.com/bedrock/pricing/) · [Bedrock DeepSeek](https://aws.amazon.com/bedrock/deepseek/) · [Vertex DeepSeek MaaS](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/maas/deepseek)
**Privacy:** [DeepSeek privacy policy](https://cdn.deepseek.com/policies/en-US/deepseek-privacy-policy.html) · [IAPP on DeepSeek/China data](https://iapp.org/news/a/deepseek-and-the-china-data-question-direct-collection-open-source-and-the-limits-of-extraterritorial-enforcement) · [Z.ai privacy policy](https://docs.z.ai/legal-agreement/privacy-policy) · [DeepInfra data privacy](https://docs.deepinfra.com/account/data-privacy) · [Anthropic retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention) · [Anthropic ZDR](https://privacy.claude.com/en/articles/8956058) · [OpenAI enterprise privacy](https://openai.com/enterprise-privacy/) · [GLM-4.6 MIT weights](https://huggingface.co/zai-org/GLM-4.6) · [DeepSeek-R1 MIT weights](https://huggingface.co/deepseek-ai/DeepSeek-R1)
**Benchmarks:** [swebench.com](https://www.swebench.com/) · [SWE-bench Pro leaderboard](https://labs.scale.com/leaderboard/swe_bench_pro_public) · [Artificial Analysis](https://artificialanalysis.ai/models/deepseek-v4-pro) · [Haiku 4.5](https://www.anthropic.com/news/claude-haiku-4-5)
**Routing:** [FrugalGPT](https://arxiv.org/abs/2305.05176) · [RouteLLM](https://lmsys.org/blog/2024-07-01-routellm/) · [Cascade Routing](https://arxiv.org/abs/2410.10347) · [Semantic-agreement cascades](https://arxiv.org/abs/2509.21837) · [LLM-judge overconfidence](https://arxiv.org/html/2508.06225v1) · [Self-preference bias](https://arxiv.org/abs/2410.21819) · [GPT-5 system card](https://openai.com/index/gpt-5-system-card/) · [Semgrep 60% triage](https://semgrep.dev/blog/2025/semgrep-is-confidently-handling-60-of-all-triage-for-users-without-reducing-coverage/) · [Semgrep 96% agreement](https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/) · [Copilot Autofix](https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/responsible-use-autofix-code-scanning)
