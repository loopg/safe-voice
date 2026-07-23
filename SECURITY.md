# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**. Do not open a public issue.

- Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository, or
- email the maintainers at the address listed on the project page.

Please include a description, reproduction steps, and impact. We aim to
acknowledge reports within a few business days.

## Scope

safe-voice is a **risk-reduction** layer, not a guarantee. Reports of concrete
bypasses (inputs that reach an LLM despite an enabled blocking layer), audit
data leakage, or fail-*closed* behavior (blocking legitimate traffic on
infrastructure failure) are especially valuable.

Note that by design the library **fails open**: an unavailable model or
translation provider allows the turn through. That is intended behavior, not a
vulnerability — see [`docs/threat-model.md`](docs/threat-model.md).

## Supported versions

The latest minor release receives security fixes. Pre-1.0, APIs may change
between minor versions.
