use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Audit, visualize, and secure Rust dependency trees.
#[derive(Parser)]
#[command(name = "tpt-cargo-vitals", version, about, long_about = None)]
struct Cli {
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

        /// Fail with a non-zero exit code on license violations.
        #[arg(long)]
        ci_mode: bool,
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
    let cli = Cli::parse();

    match cli.command {
        Command::Check { path, ci_mode } => {
            let _ = (path, ci_mode);
            eprintln!("check: not implemented yet (Phase 5)");
        }
        Command::Update => {
            eprintln!("update: not implemented yet (Phase 2)");
        }
        Command::Why { crate_name, path } => {
            let _ = (crate_name, path);
            eprintln!("why: not implemented yet (Phase 4)");
        }
    }

    ExitCode::SUCCESS
}
