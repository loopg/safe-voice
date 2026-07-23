"""Layer 2 — the ML injection scanner (optional).

The default backend is ``protectai/deberta-v3-base-prompt-injection-v2``
(~350 MB, ~26 ms warm on CPU), loaded lazily so it is only imported when you
actually use it. Install the model runtime with the ``ml`` extra::

    pip install "safe-voice[ml]"

Anything implementing the :class:`Scanner` protocol can be plugged in via
:func:`set_scanner` — a remote moderation API, a distilled local model, a stub
in tests, etc.

Graceful degradation is a core principle: if no scanner is loaded (or one fails
to load / raises at inference), every scan **fails open** (returns "safe"). The
deterministic regex + normalized layers remain the floor and are never bypassed.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Protocol, runtime_checkable

from .config import DEFAULT_ML_MODEL_PATH
from .patterns import INDIC_RE

logger = logging.getLogger("safevoice.scanner")


@runtime_checkable
class Scanner(Protocol):
    """Minimal contract for an injection scorer.

    ``score`` returns P(INJECTION) in ``[0, 1]``, or ``None`` if the scorer is
    unavailable (so callers can fail open).
    """

    def score(self, text: str) -> float | None: ...


class HFScanner:
    """Default HuggingFace text-classification backend (lazy-loaded)."""

    def __init__(self, model_path: str = DEFAULT_ML_MODEL_PATH):
        self.model_path = model_path
        self._pipeline = None
        self._lock = threading.Lock()  # HF pipelines are not documented thread-safe

    @property
    def loaded(self) -> bool:
        return self._pipeline is not None

    def load(self) -> None:
        """Load the model (idempotent). Runs a warmup inference.

        On any failure this logs and leaves the scanner unloaded — scoring will
        fail open rather than raise.
        """
        if self._pipeline is not None:
            return
        logger.info("[scanner] loading %r on CPU …", self.model_path)
        t0 = time.monotonic()
        try:
            import torch  # noqa: PLC0415 — optional dependency, imported on demand
            from transformers import pipeline as hf_pipeline  # noqa: PLC0415

            self._pipeline = hf_pipeline(
                task="text-classification",
                model=self.model_path,
                device="cpu",
                torch_dtype=torch.float32,
                truncation=True,
                max_length=512,
            )
            self._pipeline("warmup")
            logger.info("[scanner] ready in %.2fs", time.monotonic() - t0)
        except Exception as exc:  # noqa: BLE001 — degrade gracefully
            logger.warning(
                "[scanner] load failed (%s: %s). Scans will fail open — "
                "install the 'ml' extra and check the model path.",
                type(exc).__name__, exc,
            )
            self._pipeline = None

    def score(self, text: str) -> float | None:
        if self._pipeline is None:
            return None
        if not text or not text.strip():
            return 0.0
        try:
            with self._lock:
                result = self._pipeline(text[:500])[0]
            label = result["label"]
            prob = float(result["score"])
            return prob if label == "INJECTION" else 1.0 - prob
        except Exception as exc:  # noqa: BLE001 — fail open
            logger.error("[scanner] inference error (%s: %s) — failing open", type(exc).__name__, exc)
            return None


# ---------------------------------------------------------------------------
# Module-level default scanner (swappable)
# ---------------------------------------------------------------------------
_scanner: Scanner | None = None


def set_scanner(scanner: Scanner | None) -> None:
    """Install a custom scanner (or ``None`` to disable ML scanning entirely)."""
    global _scanner
    _scanner = scanner


def get_scanner() -> Scanner | None:
    return _scanner


def load_scanner(model_path: str = DEFAULT_ML_MODEL_PATH) -> Scanner:
    """Load and install the default HF scanner. Call once at startup.

    Idempotent when the current default is an :class:`HFScanner` already loaded
    for the same path.
    """
    global _scanner
    if isinstance(_scanner, HFScanner) and _scanner.loaded and _scanner.model_path == model_path:
        return _scanner
    scanner = HFScanner(model_path)
    scanner.load()
    _scanner = scanner
    return scanner


# ---------------------------------------------------------------------------
# Scan helpers (sync + async)
# ---------------------------------------------------------------------------

def injection_score(text: str) -> float | None:
    """Raw P(INJECTION) from the default scanner, or ``None`` if unavailable.

    No threshold, no script gating — used by the translation guard to score
    already-translated English text.
    """
    return _scanner.score(text) if _scanner is not None else None


def scan_voice_turn(text: str, threshold: float) -> bool:
    """Scan a user turn. Returns True (safe) or False (injection ≥ threshold).

    Fails open when no scanner is loaded. Indic-script text is skipped — the
    default model over-flags native scripts; the regex/normalized layers cover
    those instead.
    """
    if _scanner is None:
        return True
    if not text or not text.strip():
        return True
    if INDIC_RE.search(text):
        logger.debug("[scanner] Indic script — skipping ML scan")
        return True
    prob = _scanner.score(text[:500])
    if prob is None:
        return True
    if prob < threshold:
        if prob > 0.5:  # flagged but under the block bar
            logger.warning("[scanner] low-confidence injection (score=%.3f < %.2f) — allowing", prob, threshold)
        return True
    logger.warning("[scanner] injection blocked (score=%.3f ≥ %.2f)", prob, threshold)
    return False


def scan_tool_result(text: str, threshold: float) -> bool:
    """Scan external/tool content. Returns True (safe) or False (injection).

    Fails open when no scanner is loaded. No Indic skip (external content may be
    any language). Long content is head+tail sampled so a payload cannot hide
    past the model's window.
    """
    if _scanner is None:
        return True
    if not text or not text.strip():
        return True
    scan_text = text if len(text) <= 2000 else text[:1500] + " " + text[-500:]
    prob = _scanner.score(scan_text)
    if prob is None:
        return True
    if prob < threshold:
        return True
    logger.warning("[scanner] tool-content injection blocked (score=%.3f ≥ %.2f)", prob, threshold)
    return False


async def scan_voice_turn_async(text: str, threshold: float) -> bool:
    """Async wrapper — runs CPU inference off the event loop."""
    return await asyncio.to_thread(scan_voice_turn, text, threshold)


async def scan_tool_result_async(text: str, threshold: float) -> bool:
    """Async wrapper — runs CPU inference off the event loop."""
    return await asyncio.to_thread(scan_tool_result, text, threshold)


__all__ = [
    "Scanner",
    "HFScanner",
    "set_scanner",
    "get_scanner",
    "load_scanner",
    "injection_score",
    "scan_voice_turn",
    "scan_tool_result",
    "scan_voice_turn_async",
    "scan_tool_result_async",
]
