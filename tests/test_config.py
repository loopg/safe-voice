from safevoice import SecurityConfig


def test_defaults_are_safe():
    c = SecurityConfig()
    assert c.voice_guard_enabled is True
    assert 0.50 <= c.voice_guard_threshold <= 1.00
    assert c.normalized_guard_mode == "audit"
    assert c.translate_guard_enabled is False


def test_from_dict_clamps_and_ignores_bad_values():
    c = SecurityConfig.from_dict({
        "voice_guard_max_strikes": 999,       # clamp to 20
        "voice_guard_threshold": 0.1,         # clamp to 0.50
        "normalized_guard_mode": "nonsense",  # keep default
        "translate_guard_mode": "block",
        "voice_guard_enabled": "false",       # string coercion
    })
    assert c.voice_guard_max_strikes == 20
    assert c.voice_guard_threshold == 0.50
    assert c.normalized_guard_mode == "audit"       # invalid -> default kept
    assert c.translate_guard_mode == "block"
    assert c.voice_guard_enabled is False


def test_from_dict_none_returns_base():
    base = SecurityConfig(voice_guard_max_strikes=7)
    assert SecurityConfig.from_dict(None, base=base).voice_guard_max_strikes == 7


def test_from_env_reads_prefixed_vars(monkeypatch):
    monkeypatch.setenv("SAFEVOICE_VOICE_GUARD_THRESHOLD", "0.9")
    monkeypatch.setenv("SAFEVOICE_NORMALIZED_GUARD_MODE", "block")
    monkeypatch.setenv("SAFEVOICE_VOICE_GUARD_MAX_STRIKES", "99")  # clamp to 20
    c = SecurityConfig.from_env()
    assert c.voice_guard_threshold == 0.9
    assert c.normalized_guard_mode == "block"
    assert c.voice_guard_max_strikes == 20
