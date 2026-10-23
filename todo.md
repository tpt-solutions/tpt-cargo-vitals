# tpt-cargo-vitals — Project Checklist

Rust CLI supply-chain & dependency auditor. See `spec.txt` for full design.
License: dual **MIT OR Apache-2.0** (copyright: TPT Solutions).

## Phase 0 — Project Scaffolding & Repo Setup
- [x] `git init`, initial commit, `.gitignore` (Rust/Cargo defaults)
- [x] `cargo init --name tpt-cargo-vitals` (binary crate)
- [x] Add `LICENSE-MIT` and `LICENSE-APACHE` (copyright holder: TPT Solutions)
- [x] Set `Cargo.toml` `license = "MIT OR Apache-2.0"`, `authors`, `description`,
      `repository`, `keywords`, `categories`
- [x] `README.md` (project summary, install, usage examples from spec §5)
- [x] `CONTRIBUTING.md` / `CODE_OF_CONDUCT.md` (optional, lightweight) — `CONTRIBUTING.md`
      done; `CODE_OF_CONDUCT.md` skipped as optional
- [x] Choose CLI arg-parsing crate (e.g. `clap`, MIT/Apache) and scaffold
      subcommand skeleton: `check`, `update`, `why`
- [x] GitHub Actions CI: `cargo build`, `cargo test`, `cargo clippy`, `cargo fmt --check`
      on push/PR (`.github/workflows/ci.yml`; not yet run on GitHub)
- [x] `cargo-deny` or equivalent wired into CI to self-enforce the pure-MIT/Apache
      dependency policy (dogfooding Feature 2) (`deny.toml`; passes locally)
- [x] Release automation plan (e.g. `cargo-dist` or GH Actions release workflow
      producing single-binary artifacts per platform) — documented in `CONTRIBUTING.md`
- [x] Decide crates.io publish name availability for `tpt-cargo-vitals` — crates.io
      returns 404 for the name (unclaimed at time of check)

## Phase 1 — Graph Builder (Parsing & Dependency Graph)
- [x] Add `cargo_metadata` (MIT) dependency; load `Cargo.toml`/`Cargo.lock` for a
      target project path (`DependencyGraph::load` in `src/graph.rs`, via
      `cargo_metadata`, which runs `cargo metadata`)
- [x] Graph traversal without guppy: guppy was dropped (its `target-lexicon` and
      petgraph's `foldhash` dependency chains were out of policy). Graph is a plain
      adjacency list; cycles come from an iterative Tarjan SCC in `src/graph.rs`.
      No new dependencies.
- [x] Build in-memory dependency graph (nodes = crates, edges = depends-on)
- [x] Benchmark parse+graph-build time; confirm < 100ms target on a representative
      project (spec §3 Goals) — `cargo test --release -- --ignored --nocapture parse_budget`
      on this repo (84 packages): ~1.5 ms parse+build; `cargo metadata` subprocess ~70 ms
      (outside the budget)
- [x] Cycle detection pass surfaced as a diagnostic — `check` prints a
      `warning: dependency cycle` line
- [x] Platform coverage: `DependencyGraph::load` runs `cargo metadata` for the host
      plus six fixed targets (Linux, macOS, Windows × x86_64, aarch64) and unions the
      results by package id. Costs ~7 `cargo metadata` runs per `check`. Covered by the
      `platform` fixture (a `cfg(unix)` dep that a Windows host alone cannot see).
- [x] Unit tests against fixture `Cargo.toml`/`Cargo.lock` pairs (small, medium,
      large dependency trees) — `tests/fixtures/{small,medium,large}`, path-only so
      they run offline

## Phase 2 — Local-First CVE Database & Security Audit
- [x] Add `rustsec` crate to parse RustSec advisory-db format (`rustsec` 0.32,
      default features off; parses each advisory and matches versions with
      `Advisory::versions().is_vulnerable`)
- [x] Implement `tpt-cargo-vitals update`: fetch/refresh advisory-db, cache into
      local SQLite DB at `~/.tpt/vitals/cve.db` (`src/update.rs`, `src/cache.rs`).
      Downloads the GitHub tarball of `rustsec/advisory-db` and streams it into SQLite
      in one transaction. Verified against the live repo: 1,331 advisories.
- [x] Implement offline audit pass: match each resolved crate/version in the graph
      against cached advisories (no network calls during `check`) (`src/audit.rs`)
- [x] Add `rayon` (MIT) to parallelize the per-crate advisory lookup across the
      dependency tree (advisory parsing and version matching run in parallel)
- [x] Store/display DB freshness (e.g. "Local DB: 2026-09-08") and warn if stale
      past a configurable threshold (`check --max-db-age-days`, default 30)
- [x] Tests: seed a fake advisory DB, assert known-vulnerable fixture crate is
      flagged and clean crates are not (`audit.rs` tests with the `vulnerable`
      fixture). Also checked against a real advisory: `time =0.2.22` is flagged as
      RUSTSEC-2020-0071 with patched `>=0.2.23`.
- [x] Unmaintained, unsound, and notice advisories are reported separately from
      vulnerabilities, and `--ci-mode` fails only on vulnerabilities (a decision
      beyond the original list)

## Phase 3 — License Compliance Engine ("Pure MIT" Enforcer)
- [x] Extract/normalize SPDX license expressions per crate from `cargo_metadata`
      output (`src/license.rs`: a parser for `AND`, `OR`, `/`, `WITH`, and parentheses;
      `WITH` exceptions are dropped, so only the base license is judged)
- [x] Implement `--enforce-license <LIST>` / `--allow-list` policy matching
      (spec §5 Feature 2). An expression passes if it can be satisfied with the listed
      licenses: `OR` needs one side, `AND` needs both. Matching ignores case.
- [x] Implement `--ci-mode` (non-zero exit code + machine-readable summary on
      violation). The summary is tab-separated lines (`license-violation`,
      `vulnerability`) on stdout. There is no JSON yet.
- [x] Compliance summary stats (e.g. "42 MIT, 0 Apache, 0 GPL") for the dashboard
      (`by license:` counts; an expression counts toward each identifier it names).
      The project's own crates are excluded from checks.
- [x] Tests: fixture tree with a mix of MIT/Apache/GPL crates; assert correct
      pass/fail and correct counts (`tests/fixtures/licenses`)

## Phase 4 — Bloat Analysis & "Why is this here?" Command
- [ ] Compute transitive depth and total transitive-dependency count per crate
- [ ] Bloat scoring/threshold (e.g. flag crates pulling in 50+ transitive deps,
      per spec §3)
- [ ] Detect unused-but-enabled features where feasible (e.g. the `serde` +
      "derive" example in spec §5 Feature 1) — scope feasibility during
      implementation; may need a heuristic rather than full feature-usage
      analysis
- [ ] Implement `tpt-cargo-vitals why <crate>`: shortest/representative
      dependency path(s) from root to the named crate (spec §5 Feature 4)
- [ ] Tests: fixture tree with a known deep/bloated dependency chain; assert
      `why` output matches expected path

## Phase 5 — Vitals Dashboard & CLI UX
- [ ] Add `owo-colors` (MIT) + `comfy-table` (MIT) for terminal output
- [ ] Implement `tpt-cargo-vitals check` combined dashboard output matching
      spec §5 Feature 1 (security / licenses / bloat sections, ✅/⚠️/❌ status)
- [ ] Color-degrades gracefully in non-TTY / `--ci-mode` (plain text / no emoji)
- [ ] Actionable remediation text for warnings (e.g. "Consider removing unused
      feature X to save Yms compile time")
- [ ] `--help` text and man-page-style usage docs for all subcommands

## Phase 6 — Testing, Docs & Release Hardening
- [ ] End-to-end integration tests: run the built binary against real sample
      Rust projects (small/medium/large) and snapshot the dashboard output
- [ ] Performance regression test guarding the <100ms parse budget
- [ ] Document `~/.tpt/vitals/cve.db` cache location, update cadence, and
      air-gapped usage in README
- [ ] Cut `v0.1.0`, publish to crates.io, tag release
- [ ] Target release milestone: Q4 2026 (per spec.txt header)
