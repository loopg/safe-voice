"""Structured, privacy-preserving security audit events.

Every guard decision can emit a structured event. By default events are JSON and
go to the ``safevoice.audit`` logger, so they can be filtered in any log
pipeline::

    grep '"logger": "safevoice.audit"' app.log

Consumers who want events in their own telemetry (Datadog, OpenTelemetry, a
queue) can install a custom sink::

    from safevoice import audit
    audit.set_audit_sink(lambda level, record: my_metrics.emit(record))
    # audit.set_audit_sink(None)  # restore default logger

Privacy rules applied before anything leaves this module:

* URLs reduced to scheme+host+path (query string / fragment dropped)
* Text samples capped (default 120 chars)
* Params dicts sanitized recursively (URLs stripped, strings capped)
* No API keys, no full conversation content, no stack traces
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from urllib.parse import urlparse

_logger = logging.getLogger("safevoice.audit")

#: Signature: ``(level: int, record: dict) -> None``.
AuditSink = Callable[[int, dict], None]

_sink: AuditSink | None = None


def set_audit_sink(sink: AuditSink | None) -> None:
    """Install a custom audit sink, or pass ``None`` to restore the default logger.

    The record passed to the sink is already fully sanitized.
    """
    global _sink
    _sink = sink


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------

def _safe_url(url: str) -> str:
    if not url:
        return "[empty url]"
    try:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return "[invalid url]"
        return f"{p.scheme}://{p.netloc}{p.path}"
    except Exception:
        return "[unparseable url]"


def _sample(text: str, max_chars: int = 120) -> str:
    if not text:
        return ""
    text = str(text).strip()
    return text if len(text) <= max_chars else text[:max_chars] + "…"


def _sanitize_value(value: object, depth: int = 0, max_depth: int = 10) -> object:
    if depth >= max_depth:
        return "[max depth exceeded]"
    if isinstance(value, str):
        if value.startswith(("http://", "https://")):
            return _safe_url(value)
        return _sample(value, 120)
    if isinstance(value, dict):
        return _sanitize_params(value, depth + 1, max_depth)
    if isinstance(value, list):
        return [_sanitize_value(item, depth + 1, max_depth) for item in value]
    return value


def _sanitize_params(params: dict, depth: int = 0, max_depth: int = 10) -> dict:
    if not params:
        return {}
    return {key: _sanitize_value(value, depth, max_depth) for key, value in params.items()}


def _emit(level: int, event: str, **fields) -> None:
    record = {"logger": "safevoice.audit", "event": event, "ts": time.time(), **fields}
    if _sink is not None:
        try:
            _sink(level, record)
            return
        except Exception:  # a broken sink must never break the guarded request
            _logger.exception("[audit] custom sink raised — falling back to default logger")
    try:
        _logger.log(level, json.dumps(record))
    except (TypeError, ValueError):
        safe = {
            k: (repr(v) if not isinstance(v, (str, int, float, bool, type(None))) else v)
            for k, v in record.items()
        }
        _logger.log(level, json.dumps(safe))


# ---------------------------------------------------------------------------
# Public event functions
# ---------------------------------------------------------------------------

def log_tool_call(tool_name: str, params: dict, session_id: str = "", tenant_id: str = "") -> None:
    """Emit on every guarded tool/search invocation."""
    _emit(logging.INFO, "tool_call", tool=tool_name, params=_sanitize_params(params),
          session_id=session_id, tenant_id=tenant_id)


def log_tool_blocked(tool_name: str, reason: str, session_id: str = "", tenant_id: str = "") -> None:
    """Emit when query sanitization blocks a call before it happens."""
    _emit(logging.WARNING, "tool_blocked", tool=tool_name, reason=reason,
          session_id=session_id, tenant_id=tenant_id)


def log_injection_detected(source: str, text_sample: str, session_id: str = "", tenant_id: str = "") -> None:
    """Emit when an injection pattern is detected in input.

    ``source`` is one of ``user_regex``, ``user_ml``, ``user_normalized``,
    ``user_translate``, ``user_ml_allowlisted``, ``search_query``.
    """
    _emit(logging.WARNING, "injection_detected", source=source, sample=_sample(text_sample),
          session_id=session_id, tenant_id=tenant_id)


def log_normalized_guard_hit(arm: str, reason: str, text_sample: str, normalized_sample: str,
                             mode: str, blocked: bool, session_id: str = "", tenant_id: str = "") -> None:
    """Emit when the normalized (Devanagari/obfuscation) guard fires."""
    _emit(logging.WARNING if blocked else logging.INFO, "normalized_guard_hit",
          arm=arm, reason=_sample(reason), sample=_sample(text_sample),
          normalized_sample=_sample(normalized_sample), mode=mode, blocked=blocked,
          session_id=session_id, tenant_id=tenant_id)


def log_translate_guard_hit(*, decision: str, would_block: bool, second_signal: bool,
                            score: float | None, threshold: float, provider: str, latency_ms: int,
                            script_class: str, text_sample: str, translated_sample: str, mode: str,
                            session_id: str = "", tenant_id: str = "") -> None:
    """Emit when the translation guard scores a translated turn."""
    _emit(logging.WARNING if decision in ("block", "ml_only") else logging.INFO, "translate_guard_hit",
          decision=decision, would_block=would_block, second_signal=second_signal,
          score=round(score, 4) if score is not None else None, threshold=threshold, provider=provider,
          latency_ms=latency_ms, script_class=script_class, mode=mode, sample=_sample(text_sample),
          translated_sample=_sample(translated_sample), session_id=session_id, tenant_id=tenant_id)


def log_summary_rejected(summary_sample: str, session_id: str = "") -> None:
    """Emit when an LLM-generated summary fails validation and is dropped."""
    _emit(logging.WARNING, "summary_rejected", sample=_sample(summary_sample), session_id=session_id)


def log_tool_error(tool_name: str, error: Exception, session_id: str = "", tenant_id: str = "") -> None:
    """Emit on tool execution failure (opaque to the LLM, detailed here)."""
    _emit(logging.ERROR, "tool_error", tool=tool_name, error=type(error).__name__,
          detail=_sample(str(error), 200), session_id=session_id, tenant_id=tenant_id)


def log_strike(strikes: int, max_strikes: int, layer: str, shutdown: bool, session_id: str = "") -> None:
    """Emit when the orchestrator records an injection strike."""
    _emit(logging.WARNING, "strike", strikes=strikes, max_strikes=max_strikes,
          layer=layer, shutdown=shutdown, session_id=session_id)


__all__ = [
    "AuditSink",
    "set_audit_sink",
    "log_tool_call",
    "log_tool_blocked",
    "log_injection_detected",
    "log_normalized_guard_hit",
    "log_translate_guard_hit",
    "log_summary_rejected",
    "log_tool_error",
    "log_strike",
]
