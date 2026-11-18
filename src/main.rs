use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Arg, ArgAction, Command, value_parser};

mod advisory;
mod audit;
mod bloat;
mod cache;
mod dashboard;
mod deny;
mod graph;
mod license;
mod update;
mod why;

use cache::{AdvisoryCache, Error, format_date};
use dashboard::{Status, Style, table};
use graph::DependencyGraph;

/// The command-line interface. Built with clap's builder API rather than its derive
/// macros, which would pull in `unicode-ident` (Unicode-3.0) and break the pure-MIT policy.
fn cli() -> Command {
    Command::new("tpt-cargo-vitals")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Audit, visualize, and secure Rust dependency trees.")
        .long_about(
            "Audit, visualize, and secure Rust dependency trees.\n\n\
             Runs entirely locally. The only network access is `update`, which refreshes \
             the RustSec advisory cache. `check` and `why` read only from that cache and \
             from `cargo metadata`, so they work air-gapped once the cache exists.",
        )
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
                .long_about(
                    "Print a health dashboard for a Rust project: known vulnerabilities \
                     (from the local advisory cache), license compliance, and dependency \
                     bloat. Each section is marked pass, warn, or fail, and the command \
                     exits non-zero only with --ci-mode and a license violation or \
                     vulnerability.\n\n\
                     Bloat counts only the shipped build: dev-dependencies and optional \
                     dependencies that no enabled feature turns on are left out. A crate \
                     with 50 or more transitive dependencies is flagged. Run \
                     `why <crate>` to see what pulls one in.",
                )
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
                    Arg::new("dev-allow")
                        .long("dev-allow")
                        .value_name("LIST")
                        .value_delimiter(',')
                        .help(
                            "Licenses that dev-dependencies may also use, comma-separated. \
                             Applies only to dependencies no build ships, so `Apache-2.0` here \
                             allows Apache-only test helpers without allowing it in shipped code.",
                        ),
                )
                .arg(
                    Arg::new("exception")
                        .long("exception")
                        .value_name("CRATE=LICENSE")
                        .action(ArgAction::Append)
                        .help(
                            "A license one crate may use in addition to the policy, as \
                             `CRATE=LICENSE` (repeatable). It applies to that crate only.",
                        ),
                )
                .arg(
                    Arg::new("deny-config")
                        .long("deny-config")
                        .value_name("FILE")
                        .value_parser(value_parser!(PathBuf))
                        .help(
                            "The project's `deny.toml`, whose `[advisories] ignore` list names \
                             the advisories it accepts. Defaults to `deny.toml` in the project \
                             directory. Accepted advisories are listed but do not fail `--ci-mode`.",
                        ),
                )
                .arg(
                    Arg::new("ci-mode")
                        .long("ci-mode")
                        .action(ArgAction::SetTrue)
                        .help(
                            "Exit non-zero on license violations or vulnerabilities, and print a \
                             tab-separated summary of each finding to stdout. Output is plain \
                             text with no emoji or color.",
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
            Command::new("update")
                .about("Fetch and refresh the local RustSec advisory cache.")
                .long_about(
                    "Download the RustSec advisory database and replace the local cache with it. \
                     This is the only command that uses the network. It runs the system `curl`, \
                     so curl must be on PATH. The cache is replaced in one transaction, so a \
                     failed update leaves the previous data in place.\n\n\
                     Run it whenever `check` warns that the cache is stale. Nothing refreshes \
                     the cache automatically.",
                ),
        )
        .subcommand(
            Command::new("why")
                .about("Show the dependency path(s) that pull in a crate.")
                .long_about(
                    "Show how a crate gets into the build: for each compiled version, the \
                     shortest chain of dependencies from one of the project's crates down to it. \
                     Chains through dev-dependencies are marked as not shipped. Names match \
                     with `-` and `_` treated alike.",
                )
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

        Some(("check", args)) => check(args, &db_path),

        Some(("why", args)) => {
            let name = args.get_one::<String>("crate").expect("crate is required");
            let graph = DependencyGraph::load(&path_of(args))?;
            for chain in why::explain(&graph, name)? {
                let (target, through) = chain
                    .labels
                    .split_last()
                    .expect("a chain has at least one package");
                let suffix = if chain.dev_only {
                    " (dev-only: not shipped)"
                } else {
                    ""
                };
                println!("{target} is required by: {}{suffix}", through.join(" -> "));
            }
            Ok(ExitCode::SUCCESS)
        }

        _ => unreachable!("clap requires a subcommand"),
    }
}

/// `check`: loads the graph, runs the license, vulnerability, and bloat passes, and
/// prints the dashboard followed by details for each finding.
fn check(args: &clap::ArgMatches, db_path: &std::path::Path) -> Result<ExitCode, Error> {
    let path = path_of(args);
    let enforce_license: Vec<String> = values(args, "enforce-license");
    let dev_allow: Vec<String> = values(args, "dev-allow");
    let exception: Vec<String> = values(args, "exception");
    let deny_config = args.get_one::<PathBuf>("deny-config").cloned();
    let ci_mode = args.get_flag("ci-mode");
    let max_db_age_days = *args
        .get_one::<u32>("max-db-age-days")
        .expect("max-db-age-days has a default");

    // Check the cache before the slow `cargo metadata` runs, so a missing cache fails fast.
    if !db_path.exists() {
        return Err(format!(
            "no advisory database at {}; run `tpt-cargo-vitals update` first",
            db_path.display()
        )
        .into());
    }
    let cache = AdvisoryCache::open(db_path)?;
    let fetched_at = cache
        .fetched_at()?
        .ok_or("advisory database has no fetch date; run `tpt-cargo-vitals update`")?;
    let now = unix_now();
    let stale = now - fetched_at > i64::from(max_db_age_days) * 86_400;

    let graph = DependencyGraph::load(&path)?;
    for cycle in graph.cycles() {
        eprintln!("warning: dependency cycle: {}", cycle.join(" -> "));
    }

    let policy = (!enforce_license.is_empty()).then_some(enforce_license.as_slice());
    let licenses = license::check_with(&graph, policy, &dev_allow, &parse_exceptions(&exception)?);

    let findings = audit::find_vulnerabilities(&graph, &cache)?;
    let deny_path = deny_config.unwrap_or_else(|| path.join("deny.toml"));
    let accepted = deny::accepted_advisories(&deny_path)?;
    let (vulnerabilities, notices): (Vec<_>, Vec<_>) =
        findings.iter().partition(|finding| !finding.informational);
    let (accepted_findings, vulnerabilities): (Vec<_>, Vec<_>) = vulnerabilities
        .into_iter()
        .partition(|finding| accepted.contains_key(&finding.advisory_id));

    let heavy = bloat::analyze(&graph, bloat::HEAVY_THRESHOLD);

    let style = Style::detect(ci_mode);
    let db_date = format_date(fetched_at);

    // Section statuses. Accepted advisories and dependency cycles do not change them.
    let security_status = if !vulnerabilities.is_empty() {
        Status::Fail
    } else if stale || !notices.is_empty() {
        Status::Warn
    } else {
        Status::Pass
    };
    let license_status = if !licenses.violations.is_empty() {
        Status::Fail
    } else if licenses.undeclared > 0 {
        Status::Warn
    } else {
        Status::Pass
    };
    let bloat_status = if heavy.heavy.is_empty() {
        Status::Pass
    } else {
        Status::Warn
    };
    let overall = security_status.max(license_status).max(bloat_status);

    let projects: Vec<String> = graph
        .packages()
        .iter()
        .filter(|pkg| pkg.workspace)
        .map(|pkg| format!("{} v{}", pkg.name, pkg.version))
        .collect();
    println!(
        "{} {}",
        style.icon(overall),
        style.bold(&projects.join(", "))
    );

    let security_detail = format!(
        "{} vulnerabilities found (Local DB: {db_date})",
        vulnerabilities.len()
    );
    println!(
        "{}",
        style.line("├─", security_status, "Security", &security_detail)
    );

    let license_detail = license_summary(&licenses, &enforce_license);
    println!(
        "{}",
        style.line("├─", license_status, "Licenses", &license_detail)
    );

    let bloat_detail = format!(
        "{} (Max transitive depth: {}, Total crates: {})",
        heavy.level(),
        heavy.max_depth,
        heavy.total_crates
    );
    println!("{}", style.line("└─", bloat_status, "Bloat", &bloat_detail));

    // Details: each list is shown only when it has entries.
    if stale {
        eprintln!(
            "warning: advisory database is older than {max_db_age_days} days; run `tpt-cargo-vitals update`"
        );
    }
    if !licenses.violations.is_empty() {
        println!("\nLicense violations:");
        for (label, license) in &licenses.violations {
            println!("  {label}: {license}");
        }
        println!(
            "  fix: remove the dependency, allow the license with --enforce-license, \
             or add a --exception CRATE=LICENSE"
        );
    }
    if !licenses.counts.is_empty() {
        let counts: Vec<String> = licenses
            .counts
            .iter()
            .map(|(id, count)| format!("{count} {id}"))
            .collect();
        println!("\nLicenses by identifier: {}", counts.join(", "));
    }
    if licenses.undeclared > 0 {
        println!(
            "  undeclared: {} (no license in the manifest)",
            licenses.undeclared
        );
    }
    if licenses.dev_only > 0 {
        println!("  dev-only (not shipped): {}", licenses.dev_only);
    }
    if licenses.inactive > 0 {
        println!(
            "  not enabled by any feature (not compiled, not checked): {}",
            licenses.inactive
        );
    }

    if !vulnerabilities.is_empty() {
        println!("\nVulnerabilities:");
        for finding in &vulnerabilities {
            print_finding(finding);
            println!("{}", fix_hint(finding));
        }
    }
    if !accepted_findings.is_empty() {
        println!(
            "\nAccepted: {} advisories ignored by {}",
            accepted_findings.len(),
            deny_path.display()
        );
        for finding in &accepted_findings {
            let reason = &accepted[&finding.advisory_id];
            println!(
                "  {} {} {}: {reason}",
                finding.advisory_id, finding.package, finding.version
            );
        }
    }
    if !notices.is_empty() {
        println!(
            "\nNotices: {} informational advisories (unmaintained, unsound, or notice)",
            notices.len()
        );
        for finding in &notices {
            print_finding(finding);
        }
    }
    if !heavy.heavy.is_empty() {
        println!(
            "\nHeavy crates (at least {} transitive dependencies):",
            heavy.threshold
        );
        let rows: Vec<Vec<String>> = heavy
            .heavy
            .iter()
            .map(|crate_| {
                vec![
                    crate_.name.clone(),
                    crate_.version.clone(),
                    crate_.transitive.to_string(),
                    crate_.depth.to_string(),
                ]
            })
            .collect();
        println!(
            "{}",
            table(&["Crate", "Version", "Transitive deps", "Depth"], &rows)
        );
        println!(
            "  fix: run `tpt-cargo-vitals why <crate>` to see what pulls it in, and check \
             whether a lighter alternative or a smaller feature set covers your use"
        );
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

    let failed = ci_mode && overall == Status::Fail;
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// The Licenses line of the dashboard. The per-identifier counts are listed in the
/// details below it, so this line stays short.
fn license_summary(report: &license::LicenseReport, policy: &[String]) -> String {
    if policy.is_empty() {
        format!("{} dependencies checked", report.checked)
    } else {
        format!(
            "{}% compliant with {} ({} of {} dependencies)",
            percent(report.compliant(), report.checked),
            policy.join(", "),
            report.compliant(),
            report.checked,
        )
    }
}

/// The values of a repeatable or comma-separated option, or none if it was not given.
fn values(args: &clap::ArgMatches, id: &str) -> Vec<String> {
    args.get_many::<String>(id)
        .map(|values| values.cloned().collect())
        .unwrap_or_default()
}

/// The `--path` value of a subcommand. It always has a default, so it is never absent.
fn path_of(args: &clap::ArgMatches) -> PathBuf {
    args.get_one::<PathBuf>("path")
        .expect("path has a default")
        .clone()
}

/// Splits each `CRATE=LICENSE` argument. Both halves must be non-empty.
fn parse_exceptions(items: &[String]) -> Result<Vec<(String, String)>, String> {
    items
        .iter()
        .map(|item| {
            item.split_once('=')
                .filter(|(krate, license)| !krate.is_empty() && !license.is_empty())
                .map(|(krate, license)| (krate.to_owned(), license.to_owned()))
                .ok_or_else(|| format!("--exception {item:?} must be CRATE=LICENSE"))
        })
        .collect()
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

/// The remediation line shown under a vulnerability.
fn fix_hint(finding: &audit::Finding) -> String {
    match finding.patched.first() {
        Some(version) => format!("    fix: upgrade {} to {version} or later", finding.package),
        None => format!(
            "    fix: no patched version; replace {} or accept {} in deny.toml",
            finding.package, finding.advisory_id
        ),
    }
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
