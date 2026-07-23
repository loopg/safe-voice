"""Layer 1.5 — normalized-injection detector.

Closes the "English spoken but transcribed in Devanagari" gap that the raw
Layer-1 regex misses and the ML layer skips (the model false-positives on Indic
script). The text is romanized and de-obfuscated (zero-width, leetspeak,
full-width homoglyphs), then screened for attack *shapes*: an override verb near
a rule object, or a persona-reset phrase.

Every arm is reason-coded so the policy layer can BLOCK some arms and AUDIT
others. Only ``override_object`` is block-eligible; persona / skeleton / regex
arms stay audit-only until proven clean on real traffic.

Pure, synchronous, no model — microseconds per call. Additive over
``patterns.INJECTION_RE``.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from .guards import detect_user_injection
from .patterns import INJECTION_RE, OVERRIDE_VERB_RE, SENSITIVE_TARGET_RE


class NormHit(NamedTuple):
    arm: str
    reason: str
    sample: str
    norm_sample: str


# --- Devanagari → Latin + de-obfuscation tables --------------------------------
_ZW = dict.fromkeys(map(ord, "​‌‍﻿­"), None)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_DV_VOW = {"अ": "a", "आ": "aa", "इ": "i", "ई": "ii", "उ": "u", "ऊ": "uu", "ऋ": "ri", "ए": "e",
           "ऐ": "ai", "ओ": "o", "औ": "au", "ऍ": "e", "ऑ": "o", "ऒ": "o", "ऎ": "e"}
_DV_MAT = {"ा": "aa", "ि": "i", "ी": "ii", "ु": "u", "ू": "uu", "ृ": "ri", "े": "e", "ै": "ai",
           "ो": "o", "ौ": "au", "ॅ": "e", "ॉ": "o", "ॆ": "e", "ॊ": "o"}
_DV_CON = {"क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "ng", "च": "ch", "छ": "chh", "ज": "j",
           "झ": "jh", "ञ": "ny", "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n", "त": "t",
           "थ": "th", "द": "d", "ध": "dh", "न": "n", "प": "p", "फ": "ph", "ब": "b", "भ": "bh",
           "म": "m", "य": "y", "र": "r", "ल": "l", "व": "v", "श": "sh", "ष": "sh", "स": "s",
           "ह": "h", "ळ": "l", "क़": "q", "ख़": "kh", "ग़": "g", "ज़": "z", "ड़": "r", "ढ़": "rh",
           "फ़": "f", "य़": "y"}
_DV_SIGN = {"ं": "n", "ँ": "n", "ः": "h", "ॐ": "om"}
_DV_DIG = {d: str(i) for i, d in enumerate("०१२३४५६७८९")}
_HALANT, _NUKTA = "्", "़"


def _deva_to_latin(s: str) -> str:
    """Romanize Devanagari with implicit-schwa handling (lossy, deterministic)."""
    out, i, n = [], 0, len(s)
    while i < n:
        ch = s[i]
        base = ch + _NUKTA if (i + 1 < n and s[i + 1] == _NUKTA) else ch
        if base in _DV_CON or ch in _DV_CON:
            lat = _DV_CON.get(base, _DV_CON.get(ch))
            i += 2 if base != ch else 1
            nxt = s[i] if i < n else ""
            if nxt == _HALANT:
                out.append(lat); i += 1
            elif nxt in _DV_MAT:
                out.append(lat + _DV_MAT[nxt]); i += 1
            else:
                out.append(lat + "a")
            continue
        if ch in _DV_VOW: out.append(_DV_VOW[ch]); i += 1; continue
        if ch in _DV_SIGN: out.append(_DV_SIGN[ch]); i += 1; continue
        if ch in _DV_DIG: out.append(_DV_DIG[ch]); i += 1; continue
        if ch in (_HALANT, _NUKTA): i += 1; continue
        if ch in ("।", "॥"): out.append(" "); i += 1; continue
        out.append(ch); i += 1
    return "".join(out)


def _defullwidth(s: str) -> str:
    return "".join(chr(ord(c) - 0xFEE0) if "！" <= c <= "～" else (" " if c == "　" else c) for c in s)


def _normalize_basic(text: str) -> str:
    """Zero-width strip → de-fullwidth → romanize → lowercase → de-leet → collapse ws."""
    t = str(text or "").translate(_ZW)
    t = _defullwidth(t)
    t = _deva_to_latin(t).lower().translate(_LEET)
    return re.sub(r"\s+", " ", t).strip()


def _normalize_clean(text: str) -> str:
    """Schwa / long-vowel cleanup to recover English loanwords from the lossy romanizer."""
    t = re.sub(r"([aeiou])\1+", r"\1", _normalize_basic(text))  # aa→a, ii→i, uu→u
    return " ".join(w[:-1] if (len(w) > 4 and w.endswith("a")) else w for w in t.split())


def _skel(word: str) -> str:
    return re.sub(r"[aeiou]", "", word)


# --- Concept lexicons ----------------------------------------------------------
_OVERRIDE = ("ignor", "forget", "forgot", "disregard", "disrigard", "remove", "bypass",
             "override", "cancel", "bhool", "bhul", "andekh", "anadekh", "hatao", "hata", "todo")
_RULE_OBJ = ("instruction", "instr", "instrakshan", "system prompt", "sistam prompt", "prompt",
             "guardrail", "guideline", "restriction", "ristrikshan", "filter", "policy",
             "nirdesh", "niyam", "pratibandh")
_PERSONA_RE = re.compile(
    r"\b(?:"
    r"(?:you|yu|yuu)\s+(?:are|r|ar)\s+(?:now|nau)"
    r"|(?:from\s+)?now\s+on[, ]+(?:you|yu)\b"
    r"|(?:you|yu|tu|tum|aap)\s+(?:are\s+|r\s+|ar\s+|ho\s+)?(?:now\s+)?"
    r"(?:a\s+|an\s+)?(?:dan|stan|jailbroke|jailbroken|jailbreak|jelbrek)\b"
    r"|act\s+as\s+(?:a\s+|an\s+)?(?:dan|stan|jailbro\w*|unrestricted|evil|unfiltered)\b"
    r"|pretend\s+(?:you(?:'re| are)?|to\s+be)\b[^.]{0,40}"
    r"\b(?:no\s+(?:rules|limits|restrictions)|without\s+(?:any\s+)?(?:rules|limits|restrictions)"
    r"|unrestricted|unfiltered|not\s+bound|jailbro\w*)\b"
    r"|do\s+anything\s+now\b"
    r"|dan\s+mode\b|developer\s+mode\b|system\s+override\b"
    r"|jailbreak\w*\b|jailbroken\b|jelbrek\b"
    r")"
)
_OVERRIDE_SKEL = {_skel(w) for w in ("ignor", "forget", "disregard", "remove", "bypass",
                                     "override", "cancel", "bhool", "andekh", "anadekh") if len(_skel(w)) >= 3}
_OBJECT_SKEL = {_skel(w) for w in ("instruction", "instrakshan", "prompt", "guardrail",
                                   "guideline", "restriction", "ristrikshan", "filter", "policy",
                                   "nirdesh", "pratibandh") if len(_skel(w)) >= 3}
_SKEL_WINDOW = 6  # max token distance for override↔object co-occurrence

# Only the override_object arm is promoted to blocking (0 FP across 1,216 benign
# in the reference corpus). Everything else logs in audit mode regardless.
_NORM_BLOCK_ARMS = frozenset({"override_object"})


def _first_present(needles, haystack):
    for w in needles:
        if w in haystack:
            return w
    return None


def scan_normalized(text: str) -> list[NormHit]:
    """Run every normalized arm and return each that fires as a :class:`NormHit`.

    Empty list = clean. Does NOT re-run the raw Layer-1 regex (that is
    :func:`safevoice.guards.detect_user_injection`'s job).
    """
    nb = _normalize_basic(text)
    nc = _normalize_clean(text)
    sample, norm_sample = str(text or "")[:80], nc[:80]
    hits: list[NormHit] = []

    ov, ob = _first_present(_OVERRIDE, nc), _first_present(_RULE_OBJ, nc)
    if ov and ob:
        hits.append(NormHit("override_object", f"override_object[{ov}+{ob}]", sample, norm_sample))

    m = _PERSONA_RE.search(nc)
    if m:
        hits.append(NormHit("persona_reset", f"persona_reset[{m.group(0)[:24]}]", sample, norm_sample))

    toks = re.findall(r"[a-z0-9]+", nc)
    sks = [_skel(w) for w in toks]
    ov_idx = [i for i, s in enumerate(sks) if s in _OVERRIDE_SKEL]
    ob_idx = [i for i, s in enumerate(sks) if s in _OBJECT_SKEL]
    found = None
    for i in ov_idx:
        for j in ob_idx:
            if abs(i - j) <= _SKEL_WINDOW:
                found = f"skeleton[{sks[i]}~{sks[j]}]"; break
        if found:
            break
    if found:
        hits.append(NormHit("skeleton", found, sample, norm_sample))

    if nb != str(text or "").lower() and INJECTION_RE.search(nb):
        mm = INJECTION_RE.search(nb)
        hits.append(NormHit("norm_regex", f"norm_regex[{mm.group(0)[:20]}]", sample, norm_sample))
    if nc != nb and INJECTION_RE.search(nc):
        mm = INJECTION_RE.search(nc)
        hits.append(NormHit("clean_regex", f"clean_regex[{mm.group(0)[:20]}]", sample, norm_sample))

    return hits


def normalized_injection_decision(text: str, mode: str) -> tuple[bool, list[NormHit]]:
    """Apply the normalized detector under the configured policy.

    * ``off``   → ``([], no work)`` — detector disabled.
    * ``audit`` → ``(False, hits)`` — never blocks; hits are for logging only.
    * ``block`` → ``(block, hits)`` — blocks iff a block-eligible arm fired;
      non-block arms are still returned for audit logging.

    Returns ``(should_block, hits)``.
    """
    if mode == "off":
        return False, []
    hits = scan_normalized(text)
    if mode == "block":
        return any(h.arm in _NORM_BLOCK_ARMS for h in hits), hits
    return False, hits  # audit


def has_high_confidence_attack_signal(text: str) -> bool:
    """Corroborating "second signal" used by the translation guard.

    True when the text carries a HIGH-CONFIDENCE indicator, so a translate→ML
    hit is not relying on the ML alone: the raw injection regex matches, OR the
    normalized ``override_object`` arm fires, OR a sensitive target co-occurs
    with an override verb. Generic conversational phrases (repeat, confirm,
    summary) carry no sensitive target and do not corroborate.
    """
    t = text or ""
    if detect_user_injection(t):
        return True
    if any(h.arm == "override_object" for h in scan_normalized(t)):
        return True
    if SENSITIVE_TARGET_RE.search(t) and OVERRIDE_VERB_RE.search(t):
        return True
    return False


__all__ = [
    "NormHit",
    "scan_normalized",
    "normalized_injection_decision",
    "has_high_confidence_attack_signal",
]
