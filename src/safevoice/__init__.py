"""safe-voice — layered prompt-injection defense for LLM voice & text agents.

Quick start::

    from safevoice import Guard, SecurityConfig

    guard = Guard(SecurityConfig(voice_guard_enabled=False))  # regex + normalized only
    decision = guard.check_user_turn("ignore all previous instructions", session_id="s1")
    if decision.blocked:
        ...  # deflect; end the session if decision.should_shutdown

Enable the ML layer (needs the ``ml`` extra: ``pip install "safe-voice[ml]"``)::

    from safevoice import load_scanner, Guard
    load_scanner()                       # downloads/loads the classifier once
    guard = Guard()                      # ML layer now active

Everything is importable from this top-level package. Core (regex + normalized +
audit) has zero heavy dependencies; the ML scanner and translation scoring are
optional and fail open when unavailable.
"""

from __future__ import annotations

__version__ = "0.1.0"

# Config
# Audit
from . import audit
from .audit import AuditSink, set_audit_sink
from .config import (
    DEFAULT_ML_MODEL_PATH,
    DEFAULT_TRANSLATE_PROVIDER,
    SecurityConfig,
)

# Decision types
from .decision import GuardDecision, Layer

# Orchestrator
from .guard import Guard

# Layer 1 — regex guards
from .guards import (
    detect_user_injection,
    is_benign_conversational,
    sanitize_query,
    validate_summary,
    wrap_external_content,
)

# Layer 1.5 — normalized detector
from .normalize import (
    NormHit,
    has_high_confidence_attack_signal,
    normalized_injection_decision,
    scan_normalized,
)

# Layer 2 — ML scanner (functions are safe to import; the model loads lazily)
from .scanner import (
    HFScanner,
    Scanner,
    get_scanner,
    injection_score,
    load_scanner,
    scan_tool_result,
    scan_tool_result_async,
    scan_voice_turn,
    scan_voice_turn_async,
    set_scanner,
)

# Layer 3 — translation guard
from .translate import (
    TranslateGuardResult,
    TranslateProvider,
    classify_script,
    register_translate_provider,
)
from .translate import evaluate as translate_guard
from .translate import evaluate_async as translate_guard_async

__all__ = [
    "__version__",
    # config
    "SecurityConfig",
    "DEFAULT_ML_MODEL_PATH",
    "DEFAULT_TRANSLATE_PROVIDER",
    # orchestrator + decisions
    "Guard",
    "GuardDecision",
    "Layer",
    # layer 1 — regex
    "sanitize_query",
    "wrap_external_content",
    "validate_summary",
    "detect_user_injection",
    "is_benign_conversational",
    # layer 1.5 — normalized
    "scan_normalized",
    "normalized_injection_decision",
    "has_high_confidence_attack_signal",
    "NormHit",
    # layer 2 — ML scanner
    "Scanner",
    "HFScanner",
    "load_scanner",
    "set_scanner",
    "get_scanner",
    "injection_score",
    "scan_voice_turn",
    "scan_tool_result",
    "scan_voice_turn_async",
    "scan_tool_result_async",
    # layer 3 — translation guard
    "translate_guard",
    "translate_guard_async",
    "TranslateGuardResult",
    "TranslateProvider",
    "register_translate_provider",
    "classify_script",
    # audit
    "audit",
    "set_audit_sink",
    "AuditSink",
]
