"""The high-level orchestrator that ties every layer together.

:class:`Guard` runs, in order, on each user turn:

1. **Layer 1 — regex** (:func:`safevoice.guards.detect_user_injection`): any
   script, authoritative, microseconds.
2. **Layer 1.5 — normalized** (:func:`safevoice.normalize.normalized_injection_decision`):
   catches English-in-Devanagari and obfuscated overrides. Blocks only in
   ``block`` mode on the ``override_object`` arm; otherwise audits.
3. **Layer 2 — ML** (:func:`safevoice.scanner.scan_voice_turn`): only when
   ``voice_guard_enabled`` and a scanner is loaded. A hit on a benign
   conversational phrase is audited but does NOT strike.
4. **Layer 3 — translation** (:func:`safevoice.translate.evaluate`): only for
   Indic/mixed turns and only when enabled; blocks per the configured policy.

It returns a :class:`safevoice.decision.GuardDecision` — it never speaks, ends a
session, or touches your framework. You decide what to do with ``.blocked`` /
``.should_shutdown``. Injection strikes are tracked per ``session_id`` so you can
deflect a few times and then end the session.

Everything fails open: a missing/broken scanner or a translation error never
blocks a legitimate turn; the deterministic layers remain the floor.
"""

from __future__ import annotations

from . import audit
from . import scanner as _scanner
from . import translate as _translate
from .config import SecurityConfig
from .decision import GuardDecision, Layer
from .guards import detect_user_injection, is_benign_conversational
from .normalize import normalized_injection_decision
from .scanner import Scanner, injection_score


class Guard:
    """Stateful per-application injection guard.

    Parameters
    ----------
    config:
        Policy to apply. Defaults to :meth:`SecurityConfig.from_env`.
    scanner:
        Optional ML scanner to install as the process default (equivalent to
        calling :func:`safevoice.scanner.set_scanner`). If omitted, whatever was
        previously loaded via :func:`safevoice.scanner.load_scanner` is used; if
        nothing is loaded, Layer 2 fails open (regex/normalized still apply).
    """

    def __init__(self, config: SecurityConfig | None = None, *, scanner: Scanner | None = None):
        self.config = config or SecurityConfig.from_env()
        self._strikes: dict[str, int] = {}
        if scanner is not None:
            _scanner.set_scanner(scanner)

    # -- strike bookkeeping ---------------------------------------------------
    def strikes(self, session_id: str) -> int:
        """Current injection-strike count for a session."""
        return self._strikes.get(session_id, 0)

    def reset(self, session_id: str) -> None:
        """Reset a session's strike count to zero (e.g. after a clean turn)."""
        self._strikes.pop(session_id, None)

    def forget(self, session_id: str) -> None:
        """Drop all state for a session. Call on session end to avoid leaks."""
        self._strikes.pop(session_id, None)

    def _record_strike(self, layer: Layer, reason: str, session_id: str,
                       score: float | None, detail: dict) -> GuardDecision:
        strikes = self.strikes(session_id) + 1
        self._strikes[session_id] = strikes
        max_strikes = self.config.voice_guard_max_strikes
        shutdown = strikes >= max_strikes
        audit.log_strike(strikes, max_strikes, str(layer), shutdown, session_id)
        return GuardDecision(
            allowed=False, layer=layer, reason=reason, strikes=strikes,
            max_strikes=max_strikes, should_shutdown=shutdown, score=score, detail=detail,
        )

    def _allow(self, layer: Layer, session_id: str, *, reset: bool = False) -> GuardDecision:
        if reset:
            self.reset(session_id)
        return GuardDecision(
            allowed=True, layer=layer, strikes=self.strikes(session_id),
            max_strikes=self.config.voice_guard_max_strikes,
        )

    # -- shared layers 1 / 1.5 (pure, sync) -----------------------------------
    def _pre_ml(self, text: str, session_id: str, tenant_id: str) -> GuardDecision | None:
        """Run empty-check + regex + normalized. Returns a decision if one of
        those layers resolved the turn, else None (proceed to ML)."""
        sec = self.config

        if not text:
            return self._allow(Layer.EMPTY, session_id)

        # Layer 1 — regex (authoritative, any script)
        if detect_user_injection(text):
            audit.log_injection_detected("user_regex", text, session_id, tenant_id)
            return self._record_strike(Layer.REGEX, "regex injection pattern", session_id, None,
                                       {"source": "user_regex"})

        # Layer 1.5 — normalized / de-obfuscated
        blocked, hits = normalized_injection_decision(text, sec.normalized_guard_mode)
        for h in hits:
            audit.log_normalized_guard_hit(
                h.arm, h.reason, h.sample, h.norm_sample, sec.normalized_guard_mode,
                blocked and h.arm == "override_object", session_id, tenant_id,
            )
        if blocked:
            audit.log_injection_detected("user_normalized", text, session_id, tenant_id)
            return self._record_strike(Layer.NORMALIZED, "normalized override_object", session_id, None,
                                       {"arms": [h.arm for h in hits]})
        return None

    def _translate_decision(self, tg, session_id: str, tenant_id: str) -> GuardDecision | None:
        if tg is None:
            return None
        audit.log_translate_guard_hit(
            decision=tg.decision, would_block=tg.would_block, second_signal=tg.second_signal,
            score=tg.score, threshold=tg.threshold, provider=tg.provider, latency_ms=tg.latency_ms,
            script_class=tg.script_class, text_sample="", translated_sample=tg.translated or "",
            mode=self.config.translate_guard_mode, session_id=session_id, tenant_id=tenant_id,
        )
        if tg.decision == "block":
            audit.log_injection_detected("user_translate", tg.translated or "", session_id, tenant_id)
            return self._record_strike(Layer.TRANSLATE, "translation guard", session_id, tg.score,
                                       {"script_class": tg.script_class, "provider": tg.provider})
        return None

    # -- public entry points --------------------------------------------------
    def check_user_turn(self, text: str, *, session_id: str = "", tenant_id: str = "") -> GuardDecision:
        """Synchronously screen a user turn across every enabled layer."""
        text = (text or "").strip()
        sec = self.config

        pre = self._pre_ml(text, session_id, tenant_id)
        if pre is not None:
            return pre

        # Layer 2 — ML (sync)
        if sec.voice_guard_enabled and not _scanner.scan_voice_turn(text, sec.voice_guard_threshold):
            if is_benign_conversational(text):
                audit.log_injection_detected("user_ml_allowlisted", text, session_id, tenant_id)
            else:
                audit.log_injection_detected("user_ml", text, session_id, tenant_id)
                return self._record_strike(Layer.ML, "ml classifier", session_id,
                                           injection_score(text), {"source": "user_ml"})

        # Layer 3 — translation (sync)
        decided = self._translate_decision(_translate.evaluate(text, sec), session_id, tenant_id)
        if decided is not None:
            return decided

        return self._allow(Layer.CLEAN, session_id, reset=True)

    async def acheck_user_turn(self, text: str, *, session_id: str = "", tenant_id: str = "") -> GuardDecision:
        """Async variant — runs ML inference and translation off the event loop."""
        text = (text or "").strip()
        sec = self.config

        pre = self._pre_ml(text, session_id, tenant_id)
        if pre is not None:
            return pre

        if sec.voice_guard_enabled and not await _scanner.scan_voice_turn_async(text, sec.voice_guard_threshold):
            if is_benign_conversational(text):
                audit.log_injection_detected("user_ml_allowlisted", text, session_id, tenant_id)
            else:
                audit.log_injection_detected("user_ml", text, session_id, tenant_id)
                return self._record_strike(Layer.ML, "ml classifier", session_id,
                                           injection_score(text), {"source": "user_ml"})

        tg = await _translate.evaluate_async(text, sec)
        decided = self._translate_decision(tg, session_id, tenant_id)
        if decided is not None:
            return decided

        return self._allow(Layer.CLEAN, session_id, reset=True)


__all__ = ["Guard"]
