"""Return types for the high-level :class:`safevoice.guard.Guard` orchestrator."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Layer(str, Enum):
    """Which guard layer produced a decision."""

    EMPTY = "empty"            # no text to guard
    REGEX = "regex"            # Layer 1 — deterministic pattern match
    NORMALIZED = "normalized"  # Layer 1.5 — romanized/de-obfuscated match
    ML = "ml"                  # Layer 2 — model classifier
    TRANSLATE = "translate"    # Layer 3 — translate-then-score
    ALLOWLIST = "allowlist"    # benign conversational exemption
    CLEAN = "clean"            # passed every enabled layer

    def __str__(self) -> str:  # nicer log/repr output
        return self.value


@dataclass
class GuardDecision:
    """The result of running the orchestrator on one piece of user input.

    ``allowed`` is the single field most callers need. The rest explain *why*
    and support strike-based escalation (e.g. deflect a few times, then end the
    session).
    """

    allowed: bool
    layer: Layer = Layer.CLEAN
    reason: str = ""
    #: Injection-strike count for the session AFTER this turn (0 when allowed).
    strikes: int = 0
    #: Configured strike ceiling (``voice_guard_max_strikes``).
    max_strikes: int = 0
    #: True when strikes reached the ceiling — caller should end the session.
    should_shutdown: bool = False
    #: Raw P(INJECTION) when the ML/translate layer produced a score.
    score: float | None = None
    #: Free-form structured detail (arm names, translated sample, provider, …).
    detail: dict = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return not self.allowed

    def __bool__(self) -> bool:  # `if decision:` == "was it allowed?"
        return self.allowed


__all__ = ["Layer", "GuardDecision"]
