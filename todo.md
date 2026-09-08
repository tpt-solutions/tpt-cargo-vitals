# tpt-cargo-vitals — Project Checklist

Rust CLI supply-chain & dependency auditor. See `spec.txt` for full design.
License: dual **MIT OR Apache-2.0** (copyright: TPT Solutions).

## Phase 0 — Project Scaffolding & Repo Setup
- [ ] `git init`, initial commit, `.gitignore` (Rust/Cargo defaults)
- [ ] `cargo init --name tpt-cargo-vitals` (binary crate)
- [ ] Add `LICENSE-MIT` and `LICENSE-APACHE` (copyright holder: TPT Solutions)
- [ ] Set `Cargo.toml` `license = "MIT OR Apache-2.0"`, `authors`, `description`,
      `repository`, `keywords`, `categories`
- [ ] `README.md` (project summary, install, usage examples from spec §5)
- [ ] `CONTRIBUTING.md` / `CODE_OF_CONDUCT.md` (optional, lightweight)
- [ ] Choose CLI arg-parsing crate (e.g. `clap`, MIT/Apache) and scaffold
      subcommand skeleton: `check`, `update`, `why`
- [ ] GitHub Actions CI: `cargo build`, `cargo test`, `cargo clippy`, `cargo fmt --check`
      on push/PR
- [ ] `cargo-deny` or equivalent wired into CI to self-enforce the pure-MIT/Apache
      dependency policy (dogfooding Feature 2)
- [ ] Release automation plan (e.g. `cargo-dist` or GH Actions release workflow
      producing single-binary artifacts per platform)
- [ ] Decide crates.io publish name availability for `tpt-cargo-vitals`

## Phase 1 — Graph Builder (Parsing & Dependency Graph)
- [ ] Add `cargo_metadata` (MIT) dependency; load `Cargo.toml`/`Cargo.lock` for a
      target project path
- [ ] Add `guppy` (MIT/Apache, configured MIT) for graph traversal
- [ ] Build in-memory dependency graph (nodes = crates, edges = depends-on)
- [ ] Benchmark parse+graph-build time; confirm < 100ms target on a representative
      project (spec §3 Goals)
- [ ] Cycle detection pass (guppy) surfaced as a diagnostic
- [ ] Unit tests against fixture `Cargo.toml`/`Cargo.lock` pairs (small, medium,
      large dependency trees)

## Phase 2 — Local-First CVE Database & Security Audit
- [ ] Add `rustsec` crate to parse RustSec advisory-db format
- [ ] Implement `tpt-cargo-vitals update`: fetch/refresh advisory-db, cache into
      local SQLite DB at `~/.tpt/vitals/cve.db`
- [ ] Implement offline audit pass: match each resolved crate/version in the graph
      against cached advisories (no network calls during `check`)
- [ ] Add `rayon` (MIT) to parallelize the per-crate advisory lookup across the
      dependency tree
- [ ] Store/display DB freshness (e.g. "Local DB: 2026-09-08") and warn if stale
      past a configurable threshold
- [ ] Tests: seed a fake advisory DB, assert known-vulnerable fixture crate is
      flagged and clean crates are not

## Phase 3 — License Compliance Engine ("Pure MIT" Enforcer)
- [ ] Extract/normalize SPDX license expressions per crate from `cargo_metadata`
      output
- [ ] Implement `--enforce-license <LIST>` / `--allow-list` policy matching
      (spec §5 Feature 2)
- [ ] Implement `--ci-mode` (non-zero exit code + machine-readable summary on
      violation)
- [ ] Compliance summary stats (e.g. "42 MIT, 0 Apache, 0 GPL") for the dashboard
- [ ] Tests: fixture tree with a mix of MIT/Apache/GPL crates; assert correct
      pass/fail and correct counts

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
