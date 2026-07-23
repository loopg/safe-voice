import logging

from safevoice import audit


def test_url_and_text_sanitization(capture_audit):
    audit.log_tool_call(
        "web_search",
        {"url": "https://example.com/path?secret=abc#frag", "q": "x" * 300},
        session_id="s1",
    )
    _, record = capture_audit[0]
    assert record["params"]["url"] == "https://example.com/path"   # query/fragment dropped
    assert record["params"]["q"].endswith("…")                     # capped
    assert len(record["params"]["q"]) <= 121


def test_injection_sample_capped(capture_audit):
    audit.log_injection_detected("user_regex", "y" * 500, session_id="s1")
    _, record = capture_audit[0]
    assert record["event"] == "injection_detected"
    assert len(record["sample"]) <= 121


def test_broken_sink_falls_back_to_logger(caplog):
    def broken(_level, _record):
        raise RuntimeError("boom")

    audit.set_audit_sink(broken)
    with caplog.at_level(logging.WARNING, logger="safevoice.audit"):
        audit.log_tool_blocked("web_search", "blocked", session_id="s1")  # must not raise
    audit.set_audit_sink(None)
    # the fallback emitted the event to the default logger
    assert any("tool_blocked" in r.getMessage() for r in caplog.records)
