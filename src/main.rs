use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Arg, ArgAction, Command, value_parser};

mod advisory;
mod audit;
mod cache;
mod graph;
mod license;
mod update;

use cache::{AdvisoryCache, Error, format_date};
use graph::DependencyGraph;

/// The command-line interface. Built with clap's builder API rather than its derive
/// macros, which would pull in `unicode-ident` (Unicode-3.0) and break the pure-MIT policy.
fn cli() -> Command {
    Command::new("tpt-cargo-vitals")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Audit, visualize, and secure Rust dependency trees.")
        .arg_required_else_help(true)
        .subcommand_required(true)
        .arg(
            Arg::new("db")
                .long("db")
                .global(true)
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .help("Advisory cache file. Defaults to ~/.tpt/vitals/cve.db."),
        )
        .subcommand(
            Command::new("check")
                .about("Print the combined health dashboard for a project.")
                .arg(path_arg())
                .arg(
                    Arg::new("enforce-license")
                        .long("enforce-license")
                        .alias("allow-list")
                        .value_name("LIST")
                        .value_delimiter(',')
                        .help(
                            "Allowed SPDX license identifiers, comma-separated (e.g. `MIT`). \
                             Any dependency whose license cannot be satisfied with these is a violation.",
                        ),
                )
                .arg(
                    Arg::new("ci-mode")
                        .long("ci-mode")
                        .action(ArgAction::SetTrue)
                        .help(
                            "Exit non-zero on license violations or vulnerabilities, and print a \
                             tab-separated summary of each finding to stdout.",
                        ),
                )
                .arg(
                    Arg::new("max-db-age-days")
                        .long("max-db-age-days")
                        .value_name("DAYS")
                        .value_parser(value_parser!(u32))
                        .default_value("30")
                        .help("Warn when the advisory cache is older than this many days."),
                ),
        )
        .subcommand(
            Command::new("update").about("Fetch and refresh the local RustSec advisory cache."),
        )
        .subcommand(
            Command::new("why")
                .about("Show the dependency path(s) that pull in a crate.")
                .arg(
                    Arg::new("crate")
                        .required(true)
                        .help("Name of the crate to explain."),
                )
                .arg(path_arg()),
        )
}

/// The `--path` option shared by the project-level subcommands.
fn path_arg() -> Arg {
    Arg::new("path")
        .long("path")
        .value_name("PATH")
        .value_parser(value_parser!(PathBuf))
        .default_value(".")
        .help("Path to the project's Cargo.toml directory.")
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
    let matches = cli().get_matches();
    let db_path = match matches.get_one::<PathBuf>("db") {
        Some(path) => path.clone(),
        None => default_db_path()?,
    };

    match matches.subcommand() {
        Some(("update", _)) => {
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
        Some(("check", args)) => {
            let path = path_of(args);
            let enforce_license: Vec<String> = args
                .get_many::<String>("enforce-license")
                .map(|values| values.cloned().collect())
                .unwrap_or_default();
            let ci_mode = args.get_flag("ci-mode");
            let max_db_age_days = *args
                .get_one::<u32>("max-db-age-days")
                .expect("max-db-age-days has a default");

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

            let policy = (!enforce_license.is_empty()).then_some(enforce_license.as_slice());
            let licenses = license::check(&graph, policy);
            print_license_summary(&licenses, &enforce_license);

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

            if ci_mode {
                for (label, license) in &licenses.violations {
                    println!("license-violation\t{label}\t{license}");
                }
                for finding in &vulnerabilities {
                    println!(
                        "vulnerability\t{}\t{}\t{}",
                        finding.advisory_id, finding.package, finding.version
                    );
                }
            }

            let failed =
                ci_mode && (!licenses.violations.is_empty() || !vulnerabilities.is_empty());
            Ok(if failed {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }

        Some(("why", args)) => {
            let _ = (args.get_one::<String>("crate"), path_of(args));
            eprintln!("why: not implemented yet (Phase 4)");
            Ok(ExitCode::SUCCESS)
        }

        _ => unreachable!("clap requires a subcommand"),
    }
}

/// The `--path` value of a subcommand. It always has a default, so it is never absent.
fn path_of(args: &clap::ArgMatches) -> PathBuf {
    args.get_one::<PathBuf>("path")
        .expect("path has a default")
        .clone()
}

fn print_license_summary(report: &license::LicenseReport, policy: &[String]) {
    if policy.is_empty() {
        println!("Licenses: {} dependencies checked", report.checked);
    } else {
        println!(
            "Licenses: {}% compliant with {} ({} of {} dependencies)",
            percent(report.compliant(), report.checked),
            policy.join(", "),
            report.compliant(),
            report.checked,
        );
        for (label, license) in &report.violations {
            println!("  {label}: {license}");
        }
    }

    let counts: Vec<String> = report
        .counts
        .iter()
        .map(|(id, count)| format!("{count} {id}"))
        .collect();
    if !counts.is_empty() {
        println!("  by license: {}", counts.join(", "));
    }
    if report.undeclared > 0 {
        println!("  undeclared: {}", report.undeclared);
    }
}

/// `part` as a whole percentage of `total`, rounded down. 100 when there is nothing to check.
fn percent(part: usize, total: usize) -> usize {
    (part * 100).checked_div(total).unwrap_or(100)
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
