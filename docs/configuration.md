# Configuration

`SecurityConfig` is the single policy object. Construct it directly, from the
environment, or from an untrusted mapping (values are clamped, never raised).

```python
from safevoice import SecurityConfig

SecurityConfig()                        # safe defaults
SecurityConfig.from_env()               # from SAFEVOICE_* env vars
SecurityConfig.from_dict(db_row)        # per-agent/per-tenant policy from a DB
SecurityConfig.from_dict(db_row, base=SecurityConfig.from_env())  # layered
```

## Fields

| Field | Type | Default | Range / values | Meaning |
|-------|------|---------|----------------|---------|
| `voice_guard_enabled` | bool | `True` | — | Run the ML layer for this agent |
| `voice_guard_threshold` | float | `0.85` | 0.50–1.00 | P(INJECTION) at/above which ML blocks |
| `voice_guard_max_strikes` | int | `3` | 1–20 | Blocked turns before `should_shutdown` |
| `normalized_guard_mode` | str | `"audit"` | off/audit/block | Devanagari/obfuscation detector mode |
| `translate_guard_enabled` | bool | `False` | — | Enable the translation layer |
| `translate_guard_mode` | str | `"audit"` | off/audit/block | Translation layer mode |
| `translate_guard_threshold` | float | `0.85` | 0.50–1.00 | Block threshold on translated text |
| `translate_guard_timeout_ms` | int | `1200` | 100–10000 | Translation call timeout |
| `translate_guard_block_policy` | str | `"second_signal"` | second_signal/ml_only_indic | When a translated hit blocks |
| `ml_model_path` | str | protectai/…v2 | — | HF id or local path for the scanner |
| `translate_provider` | str | `"google_free"` | registered name | Translation backend |
| `translate_insecure_tls` | bool | `False` | — | Disable TLS verify (CI/sandbox only) |

## Environment variables

Every field has a `SAFEVOICE_`-prefixed env var (see `config.py` docstring).
Examples:

```bash
export SAFEVOICE_VOICE_GUARD_THRESHOLD=0.9
export SAFEVOICE_NORMALIZED_GUARD_MODE=block
export SAFEVOICE_TRANSLATE_GUARD_ENABLED=true
export SAFEVOICE_ML_MODEL_PATH=/models/my-injection-classifier
```

## Rollout recommendation

1. Start with `normalized_guard_mode="audit"` and `translate_guard_mode="audit"`.
   Nothing blocks; the `safevoice.audit` events show what *would* block.
2. Watch the `normalized_guard_hit` / `translate_guard_hit` events on real
   traffic. Confirm the `override_object` / `block` decisions are true positives.
3. Flip to `block` once you're confident. Tune `voice_guard_threshold` from the
   score distribution in your audit logs.

## Per-agent / per-tenant policy

`from_dict` is designed for policy stored in a database. Invalid or out-of-range
values are clamped and logged — a malformed row degrades safely instead of
crashing a live request.

```python
policy = SecurityConfig.from_dict(await db.fetch_security_policy(agent_id))
guard = Guard(policy)
```
