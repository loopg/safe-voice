# Contributing to safe-voice

Thanks for helping make LLM agents safer. Contributions of all sizes are welcome.

## Development setup

```bash
git clone https://github.com/safe-voice/safe-voice
cd safe-voice
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"        # includes the ML extra + test/lint tooling
```

For a fast, model-free loop you can skip the heavy ML deps:

```bash
pip install -e . pytest pytest-asyncio ruff
```

## Checks

```bash
ruff check src tests           # lint
pytest -q                      # tests (run model-free via a fake scanner)
```

Both must pass before a PR. CI runs the same checks on Python 3.10–3.13.

## Guidelines

- **Fail open.** New guard code must never raise into the caller or block on
  infrastructure failure. Degrade to "allow" and log.
- **Core stays dependency-free.** Anything importing `transformers`/`torch` must
  be lazy and confined behind the `ml` extra.
- **Tests for detection changes.** If you add or change a pattern/arm, add both a
  true-positive and a benign (no-false-positive) test.
- **Privacy.** Never log raw API keys, full conversations, or unbounded text —
  route through the `audit` helpers.
- **Expanding coverage.** New languages/patterns go in `patterns.py` with a short
  comment on provenance and a test in `tests/test_guards.py`.

## Reporting security issues

Do not open a public issue for vulnerabilities — see [`SECURITY.md`](SECURITY.md).

## License

By contributing you agree your contributions are licensed under Apache-2.0.
