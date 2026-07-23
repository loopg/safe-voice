# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

Initial release.

### Added
- Layer 1 regex guards (`sanitize_query`, `wrap_external_content`,
  `validate_summary`, `detect_user_injection`, `is_benign_conversational`)
  covering English, Hindi/Marathi, Tamil, Telugu, Bengali, and Hinglish.
- Layer 1.5 normalized detector (`scan_normalized`,
  `normalized_injection_decision`) — Devanagari romanization + de-obfuscation,
  with arm-tagged, audit/block modes.
- Layer 2 optional ML scanner (`load_scanner`, `scan_voice_turn`,
  `scan_tool_result`, sync + async) with a pluggable `Scanner` protocol and a
  lazy HuggingFace backend behind the `ml` extra.
- Layer 3 provider-pluggable translation guard (`translate_guard`,
  `register_translate_provider`).
- `Guard` orchestrator with per-session strike tracking and `GuardDecision`.
- Self-contained `SecurityConfig` (`from_env`, `from_dict` with fail-safe
  clamping).
- Structured, privacy-preserving audit with a pluggable sink (`set_audit_sink`).
- Docs, examples (quickstart, FastAPI, LiveKit), and a test suite.
