# Threat model

## What safe-voice defends against

- **Direct prompt injection** — a user telling the model to ignore its
  instructions, change persona, or reveal its system prompt, in English, five
  Indic languages, Hinglish, or obfuscated/romanized forms.
- **Indirect injection** — instructions hidden in retrieved/tool content.
  `wrap_external_content` frames such content as data; `scan_tool_result` scores
  it.
- **Two-hop / memory poisoning** — an injected instruction that survives into a
  generated summary and is replayed later as trusted context. `validate_summary`
  drops poisoned summaries before they are stored.
- **Obfuscation** — leetspeak, full-width homoglyphs, zero-width characters, and
  English-transcribed-as-Devanagari, via the normalized layer.

## What it does NOT defend against

- **Model output risks.** safe-voice screens *input*. It does not validate that
  the model's *response* is safe, factual, or policy-compliant. Add output
  checks separately.
- **Novel attacks.** The regex layer only knows enumerated phrases; the ML layer
  generalizes but is imperfect and English-centric (hence Layer 3). Determined,
  novel, or heavily paraphrased attacks may pass.
- **Tool/authorization abuse.** A guard cannot substitute for least-privilege
  tool design, per-user authorization, and rate limiting.
- **Languages beyond the covered set.** Coverage is strongest for English and
  the listed Indic languages. Other languages rely mainly on the translation
  layer (if enabled) and the English ML.

## Design guarantees

- **Fail open.** A missing/broken model, an unavailable translation provider, or
  an inference error never blocks a legitimate turn. The deterministic layers are
  the floor. This trades some recall for availability — a deliberate choice for
  real-time voice, where blocking a paying user mid-call is a serious harm.
- **No silent allowlisting.** The benign-conversational allowlist fails closed on
  any sensitive-target or extraction phrasing.
- **Privacy-preserving audit.** Events strip URLs to host+path, cap text samples
  (default 120 chars), and never log API keys or full conversations.

## Tuning for your risk posture

- Higher-stakes deployments: raise `normalized_guard_mode`/`translate_guard_mode`
  to `block`, lower `voice_guard_threshold`, and lower `voice_guard_max_strikes`.
- Lower-friction deployments: keep guards in `audit`, act only on the regex
  layer, and use the audit stream to measure attack rate before enforcing.

## Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md).
