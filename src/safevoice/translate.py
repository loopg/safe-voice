"""Layer 3 — translation guard.

Translate an Indic / non-English turn to English, then score it with the ML
scanner. Closes the native-script injection gap the raw regex misses and the
direct ML deliberately skips (it over-flags Indic script).

Runs only on turns containing Indic script, and only after the deterministic and
direct-ML layers have passed. Provider-pluggable; the keyless ``google_free``
endpoint is the default for development. Register your own with
:func:`register_translate_provider`.

Modes (``SecurityConfig.translate_guard_mode``): ``off`` | ``audit`` | ``block``.

Block policy (``SecurityConfig.translate_guard_block_policy``):

* ``second_signal`` (default, safe) — block only when the translated text ALSO
  carries a corroborating regex / normalized / sensitive-target signal. A bare
  ML hit is reported as ``ml_only`` and allowed (the model over-flags benign
  English).
* ``ml_only_indic`` — block on the ML score alone, exempting only the
  closed-class benign conversational allowlist.

Fail-open: a translation timeout/failure or an unavailable model yields decision
``error`` and the turn proceeds. The deterministic layers remain the floor.
No state, no PII storage.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import NamedTuple

from .config import SecurityConfig
from .guards import is_benign_conversational
from .normalize import has_high_confidence_attack_signal
from .patterns import INDIC_RE, LATIN_RE
from .scanner import injection_score

logger = logging.getLogger("safevoice.translate")

#: Signature: ``(text: str, timeout_s: float, insecure_tls: bool) -> Optional[str]``.
TranslateProvider = Callable[[str, float, bool], str | None]


class TranslateGuardResult(NamedTuple):
    decision: str            # block | audit | ml_only | allow | error
    would_block: bool        # translate→ML score >= threshold
    second_signal: bool      # corroborating high-confidence attack signal
    score: float | None   # P(INJECTION) on translated text (None on failure)
    threshold: float
    provider: str
    latency_ms: int
    script_class: str        # latin | indic | mixed
    translated: str | None


def classify_script(text: str) -> str:
    """Return ``indic`` (only Indic), ``mixed`` (Indic + Latin), or ``latin``."""
    has_indic = bool(INDIC_RE.search(text or ""))
    has_latin = bool(LATIN_RE.search(text or ""))
    if has_indic and has_latin:
        return "mixed"
    if has_indic:
        return "indic"
    return "latin"


def should_run(text: str) -> bool:
    """Only translate turns containing Indic script; pure-Latin turns skip (the
    direct English ML already covers them, and translation would cost an API call)."""
    return bool(text and INDIC_RE.search(text))


# ---------------------------------------------------------------------------
# Providers (pluggable)
# ---------------------------------------------------------------------------

def _ssl_context(insecure_tls: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if insecure_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _translate_google_free(text: str, timeout_s: float, insecure_tls: bool) -> str | None:
    """Keyless Google translate endpoint (auto-detect → English).

    Returns None on any failure. Intended for development/benchmarks; production
    deployments should register a keyed provider.
    """
    url = ("https://translate.googleapis.com/translate_a/single?client=gtx"
           "&sl=auto&tl=en&dt=t&q=" + urllib.parse.quote(text))
    req = urllib.request.Request(url, headers={"User-Agent": "safe-voice-translate-guard"})
    with urllib.request.urlopen(req, context=_ssl_context(insecure_tls), timeout=timeout_s) as resp:
        data = json.loads(resp.read())
    return "".join(seg[0] for seg in data[0] if seg and seg[0])


_PROVIDERS: dict[str, TranslateProvider] = {"google_free": _translate_google_free}


def register_translate_provider(name: str, provider: TranslateProvider) -> None:
    """Register a translation provider callable under ``name``.

    Select it via ``SecurityConfig.translate_provider``.
    """
    _PROVIDERS[name] = provider


def translate_to_english(text: str, config: SecurityConfig) -> tuple[str | None, int]:
    """Translate ``text`` → English using the configured provider.

    Returns ``(translated_or_None, latency_ms)``. Fail-open: any error, timeout,
    or unknown provider returns ``(None, latency)``.
    """
    fn = _PROVIDERS.get(config.translate_provider)
    t0 = time.monotonic()
    if fn is None:
        logger.warning("[translate] unknown provider %r — failing open", config.translate_provider)
        return None, 0
    try:
        out = fn(text, config.translate_guard_timeout_ms / 1000.0, config.translate_insecure_tls)
        return (out or None), int((time.monotonic() - t0) * 1000)
    except Exception as exc:  # noqa: BLE001 — fail open on ANY translation error
        logger.warning("[translate] failed (%s: %s) — failing open", type(exc).__name__, str(exc)[:120])
        return None, int((time.monotonic() - t0) * 1000)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(text: str, config: SecurityConfig | None = None) -> TranslateGuardResult | None:
    """Run the translation guard on one turn.

    Returns None when not applicable (disabled, mode=off, pure-Latin, or empty),
    otherwise a :class:`TranslateGuardResult`. Never blocks in audit mode; never
    blocks on a bare ML hit under the ``second_signal`` policy. Fail-open on
    translate/score errors (decision ``error``).
    """
    config = config or SecurityConfig.from_env()
    if not config.translate_guard_enabled or config.translate_guard_mode == "off":
        return None
    text = (text or "").strip()
    if not text or not should_run(text):
        return None

    script_class = classify_script(text)
    thr = config.translate_guard_threshold

    translated, latency_ms = translate_to_english(text, config)
    if not translated:
        return TranslateGuardResult("error", False, False, None, thr,
                                    config.translate_provider, latency_ms, script_class, None)

    score = injection_score(translated)
    if score is None:  # model not loaded → fail open
        return TranslateGuardResult("error", False, False, None, thr,
                                    config.translate_provider, latency_ms, script_class, translated)

    would_block = score >= thr
    second = has_high_confidence_attack_signal(translated) if would_block else False
    if not would_block:
        decision = "allow"
    elif config.translate_guard_mode == "audit":
        decision = "audit"
    elif config.translate_guard_block_policy == "ml_only_indic":
        decision = "ml_only" if is_benign_conversational(translated) else "block"
    else:  # second_signal — safe default
        decision = "block" if second else "ml_only"

    return TranslateGuardResult(decision, would_block, second, score, thr,
                                config.translate_provider, latency_ms, script_class, translated)


def _applicable(text: str, config: SecurityConfig) -> bool:
    return (config.translate_guard_enabled and config.translate_guard_mode != "off"
            and bool(text and should_run(text)))


async def evaluate_async(text: str, config: SecurityConfig | None = None) -> TranslateGuardResult | None:
    """Async wrapper — runs the blocking translate+score off the event loop.

    Returns None synchronously (no thread spawned) when the guard does not apply.
    """
    config = config or SecurityConfig.from_env()
    if not _applicable(text, config):
        return None
    return await asyncio.to_thread(evaluate, text, config)


__all__ = [
    "TranslateProvider",
    "TranslateGuardResult",
    "classify_script",
    "should_run",
    "register_translate_provider",
    "translate_to_english",
    "evaluate",
    "evaluate_async",
]
