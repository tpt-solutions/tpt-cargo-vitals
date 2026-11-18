//! End-to-end tests: run the built binary against the path-only fixtures.
//!
//! Each test seeds its own advisory cache, so nothing touches the network or the
//! user's `~/.tpt/vitals/cve.db`. The cache's `fetched_at` is 0 (1970-01-01), so the
//! dashboard output is deterministic.
//!
//! To regenerate the snapshots after an intended output change, run:
//! `UPDATE_SNAPSHOTS=1 cargo test --test cli`

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_tpt-cargo-vitals");
const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// A fixed `fetched_at` that makes the dashboard date 1970-01-01.
const FETCHED_AT: i64 = 0;

fn fixture(name: &str, project: &str) -> PathBuf {
    Path::new(ROOT)
        .join("tests/fixtures")
        .join(name)
        .join(project)
}

/// Writes a cache file at `path` with the schema the binary uses, holding the
/// given `(package, raw advisory)` rows and `fetched_at`.
fn seed_cache(path: &Path, fetched_at: i64, advisories: &[(&str, &str)]) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE advisories (package TEXT NOT NULL, raw TEXT NOT NULL);
         CREATE INDEX advisories_by_package ON advisories (package);
         CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
    )
    .unwrap();
    for (package, raw) in advisories {
        conn.execute(
            "INSERT INTO advisories (package, raw) VALUES (?1, ?2)",
            rusqlite::params![package, raw],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('fetched_at', ?1)",
        [fetched_at.to_string()],
    )
    .unwrap();
}

/// An advisory against `vuln-crate` that is fixed only in `patched`.
fn vuln_advisory(patched: &str) -> String {
    format!(
        "```toml\n[advisory]\nid = \"RUSTSEC-2024-0001\"\npackage = \"vuln-crate\"\n\
         date = \"2024-01-01\"\n\n[versions]\npatched = [\"{patched}\"]\n```\n\n\
         # Test advisory for vuln-crate\n"
    )
}

/// A scratch directory unique to one test, cleaned up on creation.
fn scratch(test: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

/// Compares `actual` with the named snapshot, or rewrites the snapshot when
/// `UPDATE_SNAPSHOTS` is set.
fn assert_snapshot(name: &str, actual: &str) {
    let path = Path::new(ROOT).join("tests/snapshots").join(name);
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, actual).unwrap();
        return;
    }
    let expected = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing snapshot {}; run with UPDATE_SNAPSHOTS=1",
            path.display()
        )
    });
    assert_eq!(actual, expected, "snapshot {name} differs");
}

#[test]
fn check_dashboard_matches_snapshot_for_small_tree() {
    let dir = scratch("check_small");
    let db = dir.join("cve.db");
    seed_cache(&db, FETCHED_AT, &[]);

    let project = fixture("small", "app");
    let output = run(&[
        "check",
        "--path",
        project.to_str().unwrap(),
        "--db",
        db.to_str().unwrap(),
        "--max-db-age-days",
        "100000",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_snapshot("check-small.txt", &stdout(&output));
}

#[test]
fn ci_mode_fails_on_vulnerability_and_lists_it() {
    let dir = scratch("ci_vulnerable");
    let db = dir.join("cve.db");
    // The fixture's vuln-crate is 0.1.0; a fix only in 99.0.0 leaves it vulnerable.
    let advisory = vuln_advisory(">=99.0.0");
    seed_cache(&db, FETCHED_AT, &[("vuln-crate", advisory.as_str())]);

    let project = fixture("vulnerable", "app");
    let output = run(&[
        "check",
        "--path",
        project.to_str().unwrap(),
        "--db",
        db.to_str().unwrap(),
        "--max-db-age-days",
        "100000",
        "--ci-mode",
    ]);
    let out = stdout(&output);
    assert!(!output.status.success(), "expected failure:\n{out}");
    assert!(
        out.contains("vulnerability\tRUSTSEC-2024-0001\tvuln-crate\t0.1.0"),
        "{out}"
    );
    assert!(out.contains("[fail] Security"), "{out}");
    // CI output has no emoji or color.
    assert!(!out.contains('\u{1b}') && !out.contains('❌'), "{out}");
}

#[test]
fn accepted_advisory_in_deny_toml_does_not_fail_ci() {
    let dir = scratch("ci_accepted");
    let db = dir.join("cve.db");
    let advisory = vuln_advisory(">=99.0.0");
    seed_cache(&db, FETCHED_AT, &[("vuln-crate", advisory.as_str())]);

    let deny = dir.join("deny.toml");
    fs::write(&deny, "[advisories]\nignore = [\"RUSTSEC-2024-0001\"]\n").unwrap();

    let project = fixture("vulnerable", "app");
    let output = run(&[
        "check",
        "--path",
        project.to_str().unwrap(),
        "--db",
        db.to_str().unwrap(),
        "--deny-config",
        deny.to_str().unwrap(),
        "--max-db-age-days",
        "100000",
        "--ci-mode",
    ]);
    let out = stdout(&output);
    assert!(output.status.success(), "{out}");
    assert!(out.contains("Accepted: 1 advisories"), "{out}");
    assert!(!out.contains("vulnerability\t"), "{out}");
}

#[test]
fn stale_cache_warns_on_stderr() {
    let dir = scratch("stale");
    let db = dir.join("cve.db");
    seed_cache(&db, FETCHED_AT, &[]);

    let project = fixture("small", "app");
    let output = run(&[
        "check",
        "--path",
        project.to_str().unwrap(),
        "--db",
        db.to_str().unwrap(),
    ]);
    assert!(output.status.success());
    assert!(
        stderr(&output).contains("advisory database is older than 30 days"),
        "{}",
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("[warn] Security"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn missing_cache_is_an_error_that_names_update() {
    let dir = scratch("missing");
    let db = dir.join("absent.db");

    let project = fixture("small", "app");
    let output = run(&[
        "check",
        "--path",
        project.to_str().unwrap(),
        "--db",
        db.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("tpt-cargo-vitals update"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn why_prints_the_dependency_chain() {
    let project = fixture("medium", "app");
    let output = run(&["why", "medium-x", "--path", project.to_str().unwrap()]);
    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains("medium-x 0.1.0 is required by: medium-app 0.1.0 (dev-only: not shipped)"),
        "{out}"
    );
}

#[test]
fn why_for_an_absent_crate_is_an_error() {
    let project = fixture("small", "app");
    let output = run(&["why", "not-a-crate", "--path", project.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("is not in the dependency tree"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn help_describes_every_subcommand() {
    for sub in ["check", "update", "why"] {
        let output = run(&[sub, "--help"]);
        assert!(output.status.success(), "{sub} --help failed");
        let help = stdout(&output);
        assert!(help.len() > 200, "{sub} help is too short:\n{help}");
    }
}

#[test]
fn check_runs_on_medium_and_large_trees() {
    let dir = scratch("check_trees");
    let db = dir.join("cve.db");
    seed_cache(&db, FETCHED_AT, &[]);

    for (fixture_name, workspace) in [("medium", "medium-app"), ("large", "large-app")] {
        let project = fixture(fixture_name, "app");
        let output = run(&[
            "check",
            "--path",
            project.to_str().unwrap(),
            "--db",
            db.to_str().unwrap(),
            "--max-db-age-days",
            "100000",
        ]);
        let out = stdout(&output);
        assert!(
            output.status.success(),
            "{fixture_name}: {}",
            stderr(&output)
        );
        assert!(
            out.lines()
                .next()
                .unwrap()
                .ends_with(&format!("{workspace} v0.1.0")),
            "{fixture_name} header:\n{out}"
        );
        assert!(out.contains("Bloat: Low"), "{fixture_name}:\n{out}");
    }
}
