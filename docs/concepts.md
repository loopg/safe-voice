# Concepts

safe-voice is a **defense-in-depth** filter. Each layer catches a class of
attack the others tend to miss, and every layer **fails open** — if a component
is unavailable or errors, it never blocks a legitimate turn; the deterministic
layers remain the floor.

## The layers

```
user text ─▶ Layer 1  regex          ─(hit)─▶ BLOCK + strike
          ─▶ Layer 1.5 normalized     ─(hit)─▶ BLOCK + strike   (block mode)
          ─▶ Layer 2  ML classifier   ─(hit)─▶ BLOCK + strike   (unless benign-allowlisted)
          ─▶ Layer 3  translate+score ─(hit)─▶ BLOCK + strike   (Indic turns, per policy)
          ─▶ CLEAN ─▶ allow (reset strikes)
```

### Layer 1 — Regex (`guards.py`)

A single compiled pattern covering known injection/override/persona phrases in
English, Hindi/Marathi, Tamil, Telugu, Bengali, and Hinglish. ~1 µs, zero deps,
authoritative across scripts. This is the floor that always runs.

### Layer 1.5 — Normalized (`normalize.py`)

Speech-to-text often writes spoken English in Devanagari
("ignore all previous instructions" → "इग्नोर ऑल प्रीवियस इंस्ट्रक्शन्स"), which
Layer 1 misses and the English ML skips. This layer romanizes and de-obfuscates
(zero-width, leetspeak, full-width homoglyphs) then looks for attack *shapes*:

- **override_object** — an override verb near a rule object (block-eligible)
- **persona_reset**, **skeleton**, **norm_regex**, **clean_regex** — audit-only

Only `override_object` blocks (in `block` mode). The rest are reported for
tuning. Modes: `off | audit | block`.

### Layer 2 — ML classifier (`scanner.py`)

`protectai/deberta-v3-base-prompt-injection-v2` scores novel/paraphrased
attacks the patterns don't enumerate. It runs only on Latin-script turns (it
over-flags Indic script) and only when a scanner is loaded — otherwise it fails
open. Any object with `.score(text) -> float | None` can replace it via
`set_scanner`.

### Layer 3 — Translation guard (`translate.py`)

For Indic/mixed turns, translate to English then score with Layer 2. Two
policies:

- `second_signal` (default) — block only when the translated text ALSO carries a
  corroborating regex/normalized/sensitive-target signal. A bare ML hit is
  reported `ml_only` and allowed (the model over-flags benign English).
- `ml_only_indic` — block on the ML score alone, exempting the benign allowlist.

## The benign allowlist

The ML model mis-flags ordinary voice-repair phrases ("can you repeat that?",
"show me my summary") at high confidence. `is_benign_conversational` exempts a
**closed class** of such phrases from *striking* — but fails closed on any
sensitive target or extraction phrasing, so it can never exempt a real attack.

## Strikes

Each block increments a per-`session_id` strike counter. When it reaches
`voice_guard_max_strikes`, the decision sets `should_shutdown=True` so you can
deflect a few times before ending the session. A clean turn resets the counter.
Call `guard.forget(session_id)` when a session ends.

## What safe-voice does NOT do

It doesn't speak, end sessions, call your LLM, or import your framework. It
returns a `GuardDecision`; you act on it. It also doesn't validate model
*output* — pair it with output checks and least-privilege tool design.
