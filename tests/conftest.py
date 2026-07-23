"""Shared fixtures: reset process-global scanner + audit sink around each test."""

import pytest

from safevoice import audit, scanner


class FakeScanner:
    """Deterministic stand-in for the ML backend.

    Scores P(INJECTION) = ``hit`` when ``marker`` appears in the text (case-
    insensitive), else 0.0. With ``marker=""`` it flags everything.
    """

    def __init__(self, marker: str = "mlbad", hit: float = 0.99):
        self.marker = marker.lower()
        self.hit = hit

    def score(self, text: str):
        if not text:
            return 0.0
        return self.hit if (self.marker == "" or self.marker in text.lower()) else 0.0


@pytest.fixture(autouse=True)
def _reset_globals():
    scanner.set_scanner(None)
    audit.set_audit_sink(None)
    yield
    scanner.set_scanner(None)
    audit.set_audit_sink(None)


@pytest.fixture
def capture_audit():
    """Return a list that collects every emitted (level, record) pair."""
    events: list[tuple[int, dict]] = []
    audit.set_audit_sink(lambda level, record: events.append((level, record)))
    return events


@pytest.fixture
def fake_scanner_cls():
    """Expose the FakeScanner class to tests (avoids cross-module test imports)."""
    return FakeScanner
