"""Self-contained configuration for safe-voice.

``SecurityConfig`` is the per-request/per-agent POLICY (what to run and how
strictly). It is deliberately decoupled from any host framework: build it
directly, from environment variables (:meth:`SecurityConfig.from_env`), or from
an untrusted dict such as a DB row (:meth:`SecurityConfig.from_dict`, which
clamps invalid values instead of raising).

Two field groups:

* **Policy** — ``voice_guard_*``, ``normalized_guard_mode``, ``translate_guard_*``.
  Safe to vary per agent / per tenant / per request.
* **Infrastructure** — ``ml_model_path``, ``translate_provider``,
  ``translate_insecure_tls``. Process-level; usually set once from env.

Environment variables (all optional, prefix ``SAFEVOICE_``)::

    SAFEVOICE_VOICE_GUARD_ENABLED        bool   (default true)
    SAFEVOICE_VOICE_GUARD_THRESHOLD      float  0.50–1.00 (default 0.85)
    SAFEVOICE_VOICE_GUARD_MAX_STRIKES    int    1–20      (default 3)
    SAFEVOICE_NORMALIZED_GUARD_MODE      str    off|audit|block (default audit)
    SAFEVOICE_TRANSLATE_GUARD_ENABLED    bool   (default false)
    SAFEVOICE_TRANSLATE_GUARD_MODE       str    off|audit|block (default audit)
    SAFEVOICE_TRANSLATE_GUARD_THRESHOLD  float  0.50–1.00 (default 0.85)
    SAFEVOICE_TRANSLATE_GUARD_TIMEOUT_MS int    100–10000 (default 1200)
    SAFEVOICE_TRANSLATE_GUARD_BLOCK_POLICY str  second_signal|ml_only_indic
    SAFEVOICE_ML_MODEL_PATH              str    (default protectai/…-v2)
    SAFEVOICE_TRANSLATE_PROVIDER         str    (default google_free)
    SAFEVOICE_TRANSLATE_INSECURE_TLS     bool   (default false; CI/sandbox only)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger("safevoice.config")

DEFAULT_ML_MODEL_PATH = "protectai/deberta-v3-base-prompt-injection-v2"
DEFAULT_TRANSLATE_PROVIDER = "google_free"

_GUARD_MODES = frozenset({"off", "audit", "block"})
_BLOCK_POLICIES = frozenset({"second_signal", "ml_only_indic"})


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float, lo: float, hi: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        val = float(raw)
    except ValueError:
        logger.warning("[config] %s=%r not a float — using %s", name, raw, default)
        return default
    return min(max(val, lo), hi)


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        val = int(raw)
    except ValueError:
        logger.warning("[config] %s=%r not an int — using %s", name, raw, default)
        return default
    return min(max(val, lo), hi)


def _env_choice(name: str, default: str, allowed: frozenset[str]) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    val = raw.strip().lower()
    if val not in allowed:
        logger.warning("[config] %s=%r not in %s — using %s", name, raw, sorted(allowed), default)
        return default
    return val


@dataclass
class SecurityConfig:
    """Prompt-injection guard policy + infrastructure settings.

    All defaults are safe for production. Construct directly for full control,
    or use :meth:`from_env` / :meth:`from_dict`.
    """

    # ---- Policy: ML voice/text guard (Layer 2) --------------------------------
    voice_guard_enabled: bool = True
    """Run the ML scanner on user turns for this agent (requires the ``ml`` extra)."""
    voice_guard_threshold: float = 0.85
    """P(INJECTION) at/above which the ML layer blocks. Range 0.50–1.00."""
    voice_guard_max_strikes: int = 3
    """Consecutive blocked turns before the orchestrator signals a shutdown. 1–20."""

    # ---- Policy: normalized (Devanagari/obfuscation) guard (Layer 1.5) ---------
    normalized_guard_mode: str = "audit"
    """``off`` | ``audit`` | ``block``. Catches English-in-Devanagari and leet/obfuscated overrides."""

    # ---- Policy: translation guard (Layer 3) ----------------------------------
    translate_guard_enabled: bool = False
    translate_guard_mode: str = "audit"
    """``off`` | ``audit`` | ``block``."""
    translate_guard_threshold: float = 0.85
    translate_guard_timeout_ms: int = 1200
    translate_guard_block_policy: str = "second_signal"
    """``second_signal`` (block only with a corroborating regex/normalized signal) or
    ``ml_only_indic`` (block on the ML score alone, exempting the benign allowlist)."""

    # ---- Infrastructure (process-level) ---------------------------------------
    ml_model_path: str = DEFAULT_ML_MODEL_PATH
    """HuggingFace id or local path for the ML scanner."""
    translate_provider: str = DEFAULT_TRANSLATE_PROVIDER
    translate_insecure_tls: bool = False
    """Disable TLS verification for the translate call. CI/sandbox only — never in production."""

    # Free-form escape hatch for consumers that want to stash extra context.
    extra: dict = field(default_factory=dict)

    # -------------------------------------------------------------------------
    @classmethod
    def from_env(cls) -> SecurityConfig:
        """Build from ``SAFEVOICE_*`` environment variables (all optional)."""
        return cls(
            voice_guard_enabled=_env_bool("SAFEVOICE_VOICE_GUARD_ENABLED", True),
            voice_guard_threshold=_env_float("SAFEVOICE_VOICE_GUARD_THRESHOLD", 0.85, 0.50, 1.00),
            voice_guard_max_strikes=_env_int("SAFEVOICE_VOICE_GUARD_MAX_STRIKES", 3, 1, 20),
            normalized_guard_mode=_env_choice("SAFEVOICE_NORMALIZED_GUARD_MODE", "audit", _GUARD_MODES),
            translate_guard_enabled=_env_bool("SAFEVOICE_TRANSLATE_GUARD_ENABLED", False),
            translate_guard_mode=_env_choice("SAFEVOICE_TRANSLATE_GUARD_MODE", "audit", _GUARD_MODES),
            translate_guard_threshold=_env_float("SAFEVOICE_TRANSLATE_GUARD_THRESHOLD", 0.85, 0.50, 1.00),
            translate_guard_timeout_ms=_env_int("SAFEVOICE_TRANSLATE_GUARD_TIMEOUT_MS", 1200, 100, 10_000),
            translate_guard_block_policy=_env_choice(
                "SAFEVOICE_TRANSLATE_GUARD_BLOCK_POLICY", "second_signal", _BLOCK_POLICIES
            ),
            ml_model_path=os.getenv("SAFEVOICE_ML_MODEL_PATH", DEFAULT_ML_MODEL_PATH),
            translate_provider=os.getenv("SAFEVOICE_TRANSLATE_PROVIDER", DEFAULT_TRANSLATE_PROVIDER),
            translate_insecure_tls=_env_bool("SAFEVOICE_TRANSLATE_INSECURE_TLS", False),
        )

    @classmethod
    def from_dict(cls, data: dict | None, base: SecurityConfig | None = None) -> SecurityConfig:
        """Build from an untrusted mapping (e.g. a DB row), layered over ``base``.

        FAIL-SAFE: invalid / out-of-range values are clamped or ignored and
        logged — never raised. A malformed row must not crash a live request.
        Unknown keys are ignored. Missing keys keep the ``base`` value.
        """
        cfg = base or cls.from_env()
        if not data:
            return cfg

        def _bool(key: str, cur: bool) -> bool:
            v = data.get(key, cur)
            return v if isinstance(v, bool) else str(v).strip().lower() == "true"

        def _num(key, cur, lo, hi, cast):
            try:
                v = cast(data.get(key, cur))
            except (TypeError, ValueError):
                logger.warning("[config] %s invalid (%r) — using %s", key, data.get(key), cur)
                return cur
            if not (lo <= v <= hi):
                logger.warning("[config] %s=%s out of [%s,%s] — clamping", key, v, lo, hi)
                v = min(max(v, lo), hi)
            return v

        def _choice(key, cur, allowed):
            v = str(data.get(key, cur)).strip().lower()
            if v not in allowed:
                logger.warning("[config] %s=%r not in %s — using %s", key, v, sorted(allowed), cur)
                return cur
            return v

        return cls(
            voice_guard_enabled=_bool("voice_guard_enabled", cfg.voice_guard_enabled),
            voice_guard_threshold=_num("voice_guard_threshold", cfg.voice_guard_threshold, 0.50, 1.00, float),
            voice_guard_max_strikes=_num("voice_guard_max_strikes", cfg.voice_guard_max_strikes, 1, 20, int),
            normalized_guard_mode=_choice("normalized_guard_mode", cfg.normalized_guard_mode, _GUARD_MODES),
            translate_guard_enabled=_bool("translate_guard_enabled", cfg.translate_guard_enabled),
            translate_guard_mode=_choice("translate_guard_mode", cfg.translate_guard_mode, _GUARD_MODES),
            translate_guard_threshold=_num(
                "translate_guard_threshold", cfg.translate_guard_threshold, 0.50, 1.00, float
            ),
            translate_guard_timeout_ms=_num(
                "translate_guard_timeout_ms", cfg.translate_guard_timeout_ms, 100, 10_000, int
            ),
            translate_guard_block_policy=_choice(
                "translate_guard_block_policy", cfg.translate_guard_block_policy, _BLOCK_POLICIES
            ),
            ml_model_path=str(data.get("ml_model_path", cfg.ml_model_path)),
            translate_provider=str(data.get("translate_provider", cfg.translate_provider)),
            translate_insecure_tls=_bool("translate_insecure_tls", cfg.translate_insecure_tls),
            extra=cfg.extra,
        )


__all__ = ["SecurityConfig", "DEFAULT_ML_MODEL_PATH", "DEFAULT_TRANSLATE_PROVIDER"]
