# tpt-cargo-vitals

A high-performance, local-first CLI that audits, visualizes, and secures Rust
dependency trees. Think of it as a "vitals check" for any Rust project: it flags
vulnerable crates, license violations, and dependency bloat, without sending
any metadata to external services.

> **Status:** pre-release (v0.1.0 not yet cut). The dashboard, license policy,
> offline vulnerability audit, bloat analysis, and `why` are implemented. See
> [todo.md](todo.md) for the remaining items and [spec.txt](spec.txt) for the full design.

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
# Refresh the local RustSec advisory cache (the only command that uses the network;
# it runs the system `curl`, so curl must be on PATH)
tpt-cargo-vitals update

# Combined health dashboard, fully offline
tpt-cargo-vitals check

# Fail CI if any non-MIT license is in the tree
tpt-cargo-vitals check --enforce-license MIT --ci-mode

# Explain why a crate is in the dependency tree
tpt-cargo-vitals why tokio
```

Run `tpt-cargo-vitals --help` or `tpt-cargo-vitals <subcommand> --help` for all options.

### Example output

```text
[ok] tpt-cargo-vitals v0.1.0
├─ [ok] Security: 0 vulnerabilities found (Local DB: 2026-10-23)
├─ [ok] Licenses: 100% compliant with MIT (67 of 67 dependencies)
└─ [ok] Bloat: Low (Max transitive depth: 5, Total crates: 67)
```

On an interactive terminal the sections use ✅ / ⚠️ / ❌ and color. In `--ci-mode`,
or when output is piped, they use plain `[ok]` / `[warn]` / `[fail]` with no color.
Setting `NO_COLOR` turns off color only.

Each section is `fail` on a vulnerability or license violation, `warn` on a stale
cache, an informational advisory, an undeclared license, or a crate with 50 or more
transitive dependencies. The overall line takes the worst section's status.

## Commands

### `check`

Prints the dashboard for a project, followed by details for each finding.

| Option | Meaning |
| --- | --- |
| `--path <DIR>` | Project directory containing `Cargo.toml`. Default `.`. |
| `--enforce-license <LIST>` | Allowed SPDX identifiers, comma-separated (alias `--allow-list`). |
| `--dev-allow <LIST>` | Licenses that dev-only dependencies may also use. |
| `--exception <CRATE=LICENSE>` | Lets one crate use one extra license. Repeatable. |
| `--deny-config <FILE>` | Advisory policy file. Default `deny.toml` in the project. |
| `--ci-mode` | Exit 1 on a license violation or vulnerability. Print a tab-separated summary. |
| `--max-db-age-days <DAYS>` | Warn when the cache is older than this. Default 30. |
| `--db <PATH>` | Cache file. Default `~/.tpt/vitals/cve.db`. |

Accepted advisories are the `ignore` entries in `deny.toml`. They are listed but do
not fail `--ci-mode`.

Bloat counts only the shipped build. Dev-dependencies and optional dependencies that
no enabled feature turns on are not counted.

### `why <CRATE>`

Prints the shortest dependency chain from one of the project's crates to each
compiled version of `<CRATE>`. Chains that pass only through dev-dependencies are
marked `(dev-only: not shipped)`.

```text
tokio 1.32.0 is required by: tpt-mcpbox 0.1.0 -> wasmtime 0.5.0
```

### `update`

Downloads the RustSec advisory database and replaces the local cache. This is the
only command that uses the network. It runs the system `curl`, so `curl` must be on
`PATH`.

## Local CVE cache

`tpt-cargo-vitals update` fetches the RustSec advisory database into a local
SQLite file at `~/.tpt/vitals/cve.db`. `check` and `why` read only from this
cache, so audits work air-gapped once the cache exists.

- **Location.** `~/.tpt/vitals/cve.db`, from `HOME` or, on Windows, `USERPROFILE`.
  Override with `--db <PATH>` on any command.
- **Cadence.** Nothing refreshes the cache automatically. Run `update` yourself,
  for example before CI runs or on a schedule. `check` prints a warning on stderr
  when the cache is older than `--max-db-age-days` (default 30). It still runs.
- **Air-gapped use.** Run `update` on a machine with network access. Copy the
  resulting `cve.db` to the air-gapped machine and pass it with `--db`. `check`
  and `why` never make a network call. Refreshing the cache on the air-gapped
  machine requires the same file to be copied in again.
- **Missing cache.** `check` stops with an error that names `update` when no cache
  exists. It does not run an audit with an empty database.

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
