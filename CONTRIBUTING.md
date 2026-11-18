# Contributing

Thanks for your interest in tpt-cargo-vitals. The project is hyper-focused on
being a fast, offline, Rust-only auditor, so please check [spec.txt](spec.txt)
and [todo.md](todo.md) before proposing larger changes.

## Workflow

Contributions are accepted through issues only. Open an issue describing the bug
or feature, or comment on an existing one. Code changes are made by the maintainer.

## Dependency policy

The dependency tree is **pure MIT**. A new dependency must be MIT-licensed, or
dual-licensed with an MIT option (such as `MIT OR Apache-2.0`). `cargo deny check`
enforces this via [deny.toml](deny.toml). Avoid procedural-macro crates such as
`clap`'s derive feature or `serde_derive`: they pull in `unicode-ident`, which is
Unicode-3.0 only. Adding a dependency that fails the policy needs an explicit
discussion first.

## Code style

- Follow `rustfmt` defaults and resolve all `clippy` warnings.
- Keep comments sparse and focused on *why*, not *what*.
- Add unit tests for new logic; fixture-based tests go under `tests/`.

## Releasing

Release automation is planned for Phase 0 and Phase 6 of [todo.md](todo.md):

- Versioning follows SemVer. The first public release is `v0.1.0`.
- Tagging `vX.Y.Z` on `master` triggers a GitHub Actions release workflow.
- The workflow builds single-binary artifacts per platform (Linux, macOS,
  Windows) and attaches them to the GitHub release. `cargo-dist` is the
  preferred tool for generating this workflow.
- The crate is published to crates.io from the same tag after the artifacts are green.

## Licensing

By contributing, you agree that your contributions are licensed under the
MIT and Apache-2.0 terms of this project, as described in the README.
