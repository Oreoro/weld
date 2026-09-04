# Contributing to Weld

Thanks for your interest in contributing!

## Getting Started

1. Fork the repository and create a feature branch from `main`.
2. Install the Rust toolchain (stable, edition 2021) via [rustup](https://rustup.rs).
3. Build and test locally:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Guidelines

- **Keep the policy language small.** New syntax should be justified by a use case that cannot be expressed with existing constructs. Prefer new *derived events* over new keywords.
- **Fail closed.** Anything that cannot be evaluated must deny, never allow.
- **Denials must be explainable.** If you add a rule shape, make sure `weld why` and the structured deny responses can describe it in plain language.
- **Update the docs.** Language changes belong in `docs/RULES.md`; behavioral changes belong in the README and the changelog.
- **Add tests.** Parser/synthesis changes need unit tests; enforcement changes need an integration test in `crates/weld-cli/tests/`.

## Pull requests

- One logical change per PR.
- CI must pass (build, tests, clippy, fmt).
- Describe the *why*, not just the *what*, in the PR description.

## Reporting security issues

Weld is a security tool. If you find a bypass or a soundness hole, please
report it responsibly: open a security advisory draft or contact the
maintainers privately rather than filing a public issue. We will credit
reporters in the changelog unless they prefer otherwise.

## Licensing

By contributing, you agree that your contributions will be licensed under
the MIT License that covers this project.
