"""Compiled regex corpus for the deterministic guard layers.

All patterns compile once at import time — zero per-call cost. Kept in one module
so the injection vocabulary can be reviewed, audited, and extended in a single
place.

Coverage of ``INJECTION_RE``:

* English injection / persona-override phrases (Latin script)
* Hindi / Marathi (Devanagari), Tamil, Telugu, Bengali (native scripts)
* Hinglish (Latin-script transliteration of Hindi)

Matching rules:

* ``re.IGNORECASE`` covers Latin-script patterns.
* Native-script patterns are inherently case-insensitive and are matched as
  substrings (``\\b`` word boundaries do not apply the same way across scripts).
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Layer 1 — primary injection scanner (English + 5 Indic langs + Hinglish)
# ---------------------------------------------------------------------------
INJECTION_RE = re.compile(
    r"("
    # ── English ────────────────────────────────────────────────────────────
    r"ignore\s+(previous|prior|all(\s+previous)?)\s+instructions?"
    r"|forget\s+(your|all|previous)\s+instructions?"
    r"|disregard\s+(your|all|previous)\s+instructions?"
    r"|you\s+are\s+now\s+(a\s+|an\s+)"  # require article — not "you are now able/connected"
    r"|new\s+instructions?\s*:"
    r"|system\s+override"
    r"|<\s*/?system\s*>"
    r"|act\s+as\s+if\s+you\s+(have\s+no|are\s+not)"
    r"|your\s+(new\s+)?role\s+is\s+now"
    r"|pretend\s+(you\s+are|to\s+be)\s+an?\s+AI"
    # ── Hindi / Marathi (Devanagari) ────────────────────────────────────────
    r"|पिछले\s+निर्देशों\s+को\s+अनदेखा\s+करें"
    r"|पिछले\s+सभी\s+निर्देशों\s+को\s+अनदेखा\s+करो"
    r"|सभी\s+निर्देश\s+भूल\s+जाओ"
    r"|पिछली\s+बातें\s+भूलो"
    r"|नए\s+निर्देशों?\s+का\s+पालन\s+करो"
    r"|नए\s+निर्देश"
    r"|अब\s+तुम\s+हो"
    r"|अब\s+आप\s+हैं"
    r"|सिस्टम\s+ओवरराइड"
    r"|सिस्टम\s+प्रॉम्प्ट\s+बदलो"
    r"|तुम्हारी\s+असली\s+पहचान"
    r"|तुम्हारा\s+असली\s+काम"
    r"|प्रतिबंध\s+हटाओ"
    r"|बिना\s+किसी\s+सीमा\s+के"
    r"|सभी\s+नियम\s+तोड़ो"
    r"|जेलब्रेक"
    r"|मागील\s+सूचना\s+दुर्लक्षित\s+करा"
    r"|सर्व\s+विसरा"
    r"|नवीन\s+सूचना"
    r"|आता\s+तुम्ही\s+आहात"
    r"|सिस्टम\s+ओव्हरराइड"
    # ── Tamil ───────────────────────────────────────────────────────────────
    r"|முந்தைய\s+அறிவுறுத்தல்களை\s+புறக்கணி"
    r"|எல்லாவற்றையும்\s+மறந்துவிடு"
    r"|புதிய\s+அறிவுறுத்தல்கள்"
    r"|இப்போது\s+நீ"
    r"|கட்டுப்பாடுகளை\s+அகற்று"
    r"|அமைப்பை\s+மீறு"
    # ── Telugu ────────────────────────────────────────────────────────────────
    r"|మునుపటి\s+సూచనలను\s+విస్మరించు"
    r"|అన్నీ\s+మర్చిపో"
    r"|కొత్త\s+సూచనలు"
    r"|ఇప్పుడు\s+నువ్వు"
    r"|పరిమితులను\s+తొలగించు"
    r"|సిస్టమ్\s+ఓవర్‍రైడ్"
    # ── Bengali ───────────────────────────────────────────────────────────────
    r"|আগের\s+নির্দেশ\s+উপেক্ষা\s+করুন"
    r"|সব\s+ভুলে\s+যাও"
    r"|নতুন\s+নির্দেশ"
    r"|এখন\s+তুমি"
    r"|সিস্টেম\s+ওভাররাইড"
    r"|বিধিনিষেধ\s+সরিয়ে\s+দাও"
    # ── Hinglish (Latin transliteration) ──────────────────────────────────────
    r"|ignore\s+karo\s+(sab\s+)?instructions?"
    r"|pichle\s+instructions?\s+ignore\s+karo"
    r"|pichle\s+sab\s+instructions?\s+bhool\s+jao"
    r"|sab\s+bhool\s+jao"
    r"|naye\s+instructions?\s+follow\s+karo"
    r"|naye\s+instructions?"
    r"|ab\s+tum\s+ho"
    r"|ab\s+aap\s+hain"
    r"|system\s+override\s+karo"
    r"|restrictions?\s+hatao"
    r"|limits?\s+hatao"
    r"|sab\s+rules?\s+todo"
    r"|jailbreak\s+karo"
    r"|purane\s+rules?\s+mat\s+mano"
    r"|tumhara\s+asli\s+kaam"
    r"|restrictions?\s+nahi\s+hai"
    r"|koi\s+limit\s+nahi"
    r")",
    re.IGNORECASE | re.UNICODE,
)

# ---------------------------------------------------------------------------
# Benign-allowlist support patterns (voice-UX false-positive guard)
# ---------------------------------------------------------------------------

# A sensitive target token forces the benign allowlist to fail closed.
SENSITIVE_TARGET_RE = re.compile(
    r"\b(system|prompt|instruction|instructions|directive|directives|rule|rules|"
    r"guideline|guidelines|policy|policies|guardrail|guardrails|restriction|"
    r"restrictions|filter|filters|developer|persona|configuration|config|training|"
    r"jailbreak)\b",
    re.IGNORECASE,
)

# Extraction-style vocabulary that must NEVER be allowlisted.
REPEAT_INJECTION_RE = re.compile(
    r"\brepeat\s+(?:after|everything|all|back"
    r"|the\s+(?:following|above|previous|first|last|text|words?|message|sentence|thing|line|lines))\b"
    r"|\b(?:verbatim|word\s+for\s+word|above|initial|omit|reveal|hidden|"
    r"password|passwords|secret|secrets|told|"
    r"ignore|disregard|override|bypass|forget)\b",
    re.IGNORECASE,
)

# Closed-class benign voice repair / confirmation / navigation phrases.
BENIGN_CONVERSATIONAL_RE = re.compile(
    r"(?:"
    r"\brepeat\s+(?:that|it|this|yourself|again)\b"
    r"|\bsay\s+(?:that|it|this)\s+again\b"
    r"|\bsay\s+(?:that|it)\s+(?:one\s+more\s+time|once\s+more)\b"
    r"|\b(?:can|could|would|will)\s+you\s+(?:please\s+)?repeat\b"
    r"|\bone\s+more\s+time\b|\bonce\s+more\b|\bcome\s+again\b|\bpardon\b"
    r"|\b(?:didn'?t|did\s+not|couldn'?t|could\s+not)\s+(?:catch|hear|get|understand)\b"
    r"|\bwhat\s+(?:did|was)\s+(?:you|that|the\s+last\s+thing)\b.*\b(?:say|said)\b"
    r"|\bwhat\s+was\s+that\b"
    r"|\bspeak\s+(?:slowly|slower|louder|up|more\s+slowly)\b"
    r"|\bconfirm\s+my\s+(?:details|info|information|number|name|application)\b"
    r"|\blet\s+me\s+confirm\b"
    r"|\b(?:show|tell|give)\s+me\s+(?:the\s+|a\s+|my\s+)?(?:\w+\s+)?summary\b"
    r"|\b(?:go\s+back|start\s+over)\b"
    r")",
    re.IGNORECASE,
)

# Override verbs for the translation-guard second-signal corroborator.
OVERRIDE_VERB_RE = re.compile(
    r"\b(ignore|forget|disregard|bypass|reveal|show|repeat|override|leak|expose|"
    r"print|dump|disable|remove|change|modify)\b",
    re.IGNORECASE,
)

# Indic script Unicode ranges — Devanagari, Bengali, Gujarati, Odia, Tamil,
# Telugu, Kannada, Malayalam. Shared by the ML scanner (skip) and translate guard.
INDIC_RE = re.compile(r"[ऀ-ॿঀ-৿઀-૿଀-୿஀-௿ఀ-౿ಀ-೿ഀ-ൿ]")
LATIN_RE = re.compile(r"[A-Za-z]")

__all__ = [
    "INJECTION_RE",
    "SENSITIVE_TARGET_RE",
    "REPEAT_INJECTION_RE",
    "BENIGN_CONVERSATIONAL_RE",
    "OVERRIDE_VERB_RE",
    "INDIC_RE",
    "LATIN_RE",
]
