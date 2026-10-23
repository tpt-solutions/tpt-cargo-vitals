# tpt-cargo-vitals

A high-performance, local-first CLI that audits, visualizes, and secures Rust
dependency trees. Think of it as a "vitals check" for any Rust project: it flags
vulnerable crates, license violations, and dependency bloat, without sending
any metadata to external services.

> **Status:** early development (v0.1.0 in progress). Subcommands are scaffolded;
> the audit engine is not implemented yet. See [todo.md](todo.md) for the
> phased roadmap and [spec.txt](spec.txt) for the full design.

## Why

AI agents and developers add dependencies without seeing the full transitive
tree. That leads to:

- **Security risk:** crates with known CVEs or compromised maintainers.
- **License contamination:** GPL or otherwise non-permissive crates slipping into
  a pure-MIT project.
- **Compile-time bloat:** unnecessary transitive dependencies that slow CI and
  grow binaries.

## Goals

- Parse `Cargo.toml` and `Cargo.lock` in under 100ms.
- Run audits **offline** against a local CVE cache (no network during `check`).
- Enforce license policy, e.g. `--enforce-license MIT`.
- Highlight bloat, such as crates pulling in 50+ transitive dependencies.
- Ship as a single binary with zero telemetry.

## Install

```sh
cargo install tpt-cargo-vitals
```

Or build from source:

```sh
git clone https://github.com/tpt-solutions/tpt-cargo-vitals
cd tpt-cargo-vitals
cargo build --release
```

## Usage

```sh
# Refresh the local RustSec advisory cache (the only command that uses the network)
tpt-cargo-vitals update

# Combined health dashboard, fully offline
tpt-cargo-vitals check

# Fail CI if any non-MIT license is in the tree
tpt-cargo-vitals check --enforce-license MIT --ci-mode

# Explain why a crate is in the dependency tree
tpt-cargo-vitals why tokio
```

Run `tpt-cargo-vitals --help` or `tpt-cargo-vitals <subcommand> --help` for all options.

### Planned output

```text
✅ tpt-mcpbox v0.1.0
├─ 🛡️ Security: 0 vulnerabilities found (Local DB: 2026-09-08)
├─ ⚖️ Licenses: 100% compliant (42 MIT, 0 Apache, 0 GPL)
└─ 📦 Bloat: Low (Max transitive depth: 4, Total crates: 45)
```

## Local CVE cache

`tpt-cargo-vitals update` fetches the RustSec advisory database into a local
SQLite file at `~/.tpt/vitals/cve.db`. `check` and `why` read only from this
cache, so audits work air-gapped once the cache exists.

*Cache cadence and air-gapped setup will be documented once the update command lands.*

## Development

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check        # requires cargo-deny; enforces the license policy in deny.toml
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

Dual-licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option. Copyright © TPT Solutions.
