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
- [x] Load `Cargo.toml`/`Cargo.lock` for a
      target project path (`DependencyGraph::load` in `src/graph.rs`, which runs
      `cargo metadata` and parses its JSON with the MIT-licensed `json` crate)
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
- [x] Parse the RustSec advisory-db format (`src/advisory.rs`, using `toml` and
      `semver`). Originally the `rustsec` crate; it was replaced for pure MIT, since
      it pulls in the ICU stack (Unicode-3.0).
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
- [x] Extract/normalize SPDX license expressions per crate from `cargo metadata`
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
- [x] Compute transitive depth and total transitive-dependency count per crate
      (`src/bloat.rs`: depth is the shortest shipped-edge distance from a project crate;
      the count is distinct shipped packages reachable from the crate)
- [x] Bloat scoring/threshold (e.g. flag crates pulling in 50+ transitive deps,
      per spec §3) — `bloat::HEAVY_THRESHOLD` = 50; a crate at or above it is `heavy`
      and turns the Bloat section to `warn`
- [ ] Detect unused-but-enabled features where feasible (e.g. the `serde` +
      "derive" example in spec §5 Feature 1) — **deferred.** Knowing that a feature is
      unused needs to know which items of a crate each feature gates and whether the
      project's source uses them. Name-matching on source would give false positives
      on the exact cases the spec cares about, so this is not built yet.
- [x] Implement `tpt-cargo-vitals why <crate>`: shortest dependency path from a project
      crate to each compiled version (`src/why.rs`; spec §5 Feature 4). Dev-only chains
      are marked. Inactive optional dependencies are reported as not compiled.
- [x] Tests: `tests/fixtures/{small,medium}` for path and dev-only chains;
      `bloat` tests with a lowered threshold, since the fixtures are too small to reach 50

## Phase 5 — Vitals Dashboard & CLI UX
- [x] Add `owo-colors` (MIT) + `comfy-table` (MIT) for terminal output
      (`src/dashboard.rs`; the heavy-crate table uses comfy-table)
- [x] Implement `tpt-cargo-vitals check` combined dashboard output matching
      spec §5 Feature 1 (security / licenses / bloat sections, ✅/⚠️/❌ status) —
      the header shows the worst status; each section has its own
- [x] Color-degrades gracefully in non-TTY / `--ci-mode` (plain text / no emoji)
      — also honours `NO_COLOR`
- [x] Actionable remediation text for warnings — vulnerabilities name the patched
      version (or say there is none), license violations list the three options,
      heavy crates point at `why`. The spec's "save Yms compile time" wording is
      not used: it needs the unused-feature analysis that is deferred above.
- [x] `--help` text and man-page-style usage docs for all subcommands — extended
      `long_help` per subcommand and a Commands section in the README. No generated
      man page is shipped.

## Phase 6 — Testing, Docs & Release Hardening
- [x] End-to-end integration tests: run the built binary against real sample
      Rust projects (small/medium/large) and snapshot the dashboard output —
      `tests/cli.rs`, with `tests/snapshots/check-small.txt`. Each test seeds its own
      advisory cache, so nothing touches the network or `~/.tpt`.
- [x] Performance regression test guarding the <100ms parse budget — `parse_budget`
      now runs in the normal test suite (it was `#[ignore]`d)
- [x] Document `~/.tpt/vitals/cve.db` cache location, update cadence, and
      air-gapped usage in README
- [ ] Cut `v0.1.0`, publish to crates.io, tag release — **not done.** Publishing and
      tagging are outward-facing and cannot be undone, so they wait for an explicit go-ahead.
- [ ] Target release milestone: Q4 2026 (per spec.txt header)
