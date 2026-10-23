use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

mod audit;
mod cache;
mod graph;
mod update;

use cache::{AdvisoryCache, Error, format_date};
use graph::DependencyGraph;

/// Audit, visualize, and secure Rust dependency trees.
#[derive(Parser)]
#[command(name = "tpt-cargo-vitals", version, about, long_about = None)]
struct Cli {
    /// Advisory cache file. Defaults to ~/.tpt/vitals/cve.db.
    #[arg(long, global = true, value_name = "PATH")]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the combined health dashboard for a project.
    Check {
        /// Path to the project's Cargo.toml directory.
        #[arg(long, default_value = ".")]
        path: PathBuf,

        /// Exit non-zero when vulnerabilities are found.
        #[arg(long)]
        ci_mode: bool,

        /// Warn when the advisory cache is older than this many days.
        #[arg(long, default_value_t = 30, value_name = "DAYS")]
        max_db_age_days: u32,
    },
    /// Fetch and refresh the local RustSec advisory cache.
    Update,
    /// Show the dependency path(s) that pull in a crate.
    Why {
        /// Name of the crate to explain.
        crate_name: String,

        /// Path to the project's Cargo.toml directory.
        #[arg(long, default_value = ".")]
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, Error> {
    let cli = Cli::parse();
    let db_path = match cli.db {
        Some(path) => path,
        None => default_db_path()?,
    };

    match cli.command {
        Command::Update => {
            let mut cache = AdvisoryCache::open(&db_path)?;
            let now = unix_now();
            let count = update::fetch(&mut cache, update::ADVISORY_DB_URL, now)?;
            println!(
                "Advisory database updated: {count} advisories ({})",
                format_date(now)
            );
            Ok(ExitCode::SUCCESS)
        }

        // The dashboard is Phase 5. For now `check` reports graph shape,
        // dependency cycles, and known vulnerabilities.
        Command::Check {
            path,
            ci_mode,
            max_db_age_days,
        } => {
            let graph = DependencyGraph::load(&path)?;
            println!(
                "{} packages, {} dependency links, {} workspace member(s)",
                graph.package_count(),
                graph.link_count(),
                graph.workspace_members().len(),
            );
            for cycle in graph.cycles() {
                eprintln!("warning: dependency cycle: {}", cycle.join(" -> "));
            }

            if !db_path.exists() {
                return Err(format!(
                    "no advisory database at {}; run `tpt-cargo-vitals update` first",
                    db_path.display()
                )
                .into());
            }
            let cache = AdvisoryCache::open(&db_path)?;
            let fetched_at = cache
                .fetched_at()?
                .ok_or("advisory database has no fetch date; run `tpt-cargo-vitals update`")?;
            let now = unix_now();
            if now - fetched_at > i64::from(max_db_age_days) * 86_400 {
                eprintln!(
                    "warning: advisory database is older than {max_db_age_days} days; run `tpt-cargo-vitals update`"
                );
            }

            let findings = audit::find_vulnerabilities(&graph, &cache)?;
            let (vulnerabilities, notices): (Vec<_>, Vec<_>) =
                findings.iter().partition(|finding| !finding.informational);

            let db_date = format_date(fetched_at);
            println!(
                "Security: {} vulnerabilities found (Local DB: {db_date})",
                vulnerabilities.len()
            );
            for finding in &vulnerabilities {
                print_finding(finding);
            }
            if !notices.is_empty() {
                println!(
                    "Notices: {} informational advisories (unmaintained, unsound, or notice)",
                    notices.len()
                );
                for finding in &notices {
                    print_finding(finding);
                }
            }

            Ok(if ci_mode && !vulnerabilities.is_empty() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }

        Command::Why { crate_name, path } => {
            let _ = (crate_name, path);
            eprintln!("why: not implemented yet (Phase 4)");
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn print_finding(finding: &audit::Finding) {
    let patched = if finding.patched.is_empty() {
        "no patched version".to_owned()
    } else {
        format!("patched: {}", finding.patched.join(", "))
    };
    println!(
        "  {} {} {}: {} ({patched})",
        finding.advisory_id, finding.package, finding.version, finding.title
    );
}

/// `~/.tpt/vitals/cve.db`, from `HOME` or, on Windows, `USERPROFILE`.
fn default_db_path() -> Result<PathBuf, Error> {
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .ok_or("cannot find a home directory; pass --db <PATH>")?;
    Ok(PathBuf::from(home)
        .join(".tpt")
        .join("vitals")
        .join("cve.db"))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}
