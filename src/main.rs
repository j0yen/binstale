//! `binstale` — running-binary staleness detector.
//!
//! Classifies running processes as `fresh | deleted-exe | inode-drift | prov-stale`
//! using `/proc` and provfs xattr signals.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::process;

use clap::{Parser, Subcommand, ValueEnum};

use crate::error::exit_code;
use crate::output::{OutputFormat, ProcessVerdict};
use crate::proc::{collect_proc_info, scan_matching_pids};
use crate::verdict::classify;

mod error;
mod output;
mod proc;
mod verdict;

/// Default daemon regex for `binstale scan` with no `--match`.
const DEFAULT_MATCH: &str = r"^(agorabus|recalld|wm-(audio|dialog|stt|tts))$";

/// Running-binary staleness detector.
///
/// Classifies running processes as: fresh | deleted-exe | inode-drift | prov-stale
///
/// Verdict taxonomy:
///   deleted-exe  — /proc/PID/exe ends in " (deleted)"; kernel unlinked the binary.
///   inode-drift  — same path, but on-disk inode changed since exec (atomic rename).
///   prov-stale   — inode matches, but provfs user.prov.ts (or mtime) is newer than process start.
///   fresh        — none of the above conditions detected.
///
/// Exit codes: 0=all-fresh, 1=any-stale, 2=usage/IO error
#[derive(Debug, Parser)]
#[command(
    name = "binstale",
    version = "0.1.0",
    about = "Running-binary staleness detector",
    long_about = "Classifies running processes as: fresh | deleted-exe | inode-drift | prov-stale\n\
    \n\
    Verdict taxonomy:\n  \
      deleted-exe  — /proc/PID/exe ends in \" (deleted)\"; kernel unlinked the binary.\n  \
      inode-drift  — same path but on-disk inode changed since exec (atomic rename).\n  \
      prov-stale   — inode matches but provfs user.prov.ts (or mtime) is newer than proc start.\n  \
      fresh        — none of the above.\n\
    \n\
    Exit codes: 0=all-fresh, 1=any-stale, 2=usage/IO error"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check the staleness verdict for a single process by PID.
    ///
    /// Exit codes: 0=fresh, 1=stale, 2=error (process not found or I/O error)
    Check {
        /// PID of the process to check.
        pid: u32,

        /// Output format: table (human-readable) or json (machine-parseable).
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// Scan all running processes matching a regex and report verdicts.
    ///
    /// Matches against /proc/PID/comm and argv[0]. Default regex covers
    /// the wintermute daemon set: agorabus, recalld, wm-{audio,dialog,stt,tts}.
    ///
    /// Exit codes: 0=all-fresh (or no matches), 1=any-stale, 2=error
    Scan {
        /// Regex to match against process comm and argv[0].
        /// Default: ^(agorabus|recalld|wm-(audio|dialog|stt|tts))$
        #[arg(long, default_value = DEFAULT_MATCH)]
        r#match: String,

        /// Output format: table (human-readable) or json (machine-parseable).
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },
}

/// Output format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable table output.
    Table,
    /// JSON array output (one object per process).
    Json,
}

impl From<Format> for OutputFormat {
    fn from(f: Format) -> Self {
        match f {
            Format::Table => Self::Table,
            Format::Json => Self::Json,
        }
    }
}

fn main() {
    let cli = Cli::parse();

    let exit = match cli.command {
        Command::Check { pid, format } => run_check(pid, format.into()),
        Command::Scan { r#match: pattern, format } => run_scan(&pattern, format.into()),
    };

    process::exit(exit);
}

/// Run the `check` subcommand for a single PID.
fn run_check(pid: u32, format: OutputFormat) -> i32 {
    match collect_proc_info(pid) {
        Err(crate::error::BinstaleError::ProcessNotFound { pid: p }) => {
            eprintln!("binstale: process not found: PID {p}");
            exit_code::ERROR
        }
        Err(e) => {
            eprintln!("binstale: error reading /proc/{pid}: {e}");
            exit_code::ERROR
        }
        Ok(info) => {
            let (verdict, evidence) = classify(&info);
            let pv = ProcessVerdict::from_info_and_verdict(&info, verdict.clone(), evidence);
            if let Err(e) = output::print_verdicts(&[pv], format) {
                eprintln!("binstale: output error: {e}");
                return exit_code::ERROR;
            }
            if verdict == crate::verdict::Verdict::Fresh {
                exit_code::FRESH
            } else {
                exit_code::STALE
            }
        }
    }
}

/// Run the `scan` subcommand.
fn run_scan(pattern: &str, format: OutputFormat) -> i32 {
    let re = match regex::Regex::new(pattern) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("binstale: invalid regex '{pattern}': {e}");
            return exit_code::ERROR;
        }
    };

    let pids = match scan_matching_pids(&re) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("binstale: scan error: {e}");
            return exit_code::ERROR;
        }
    };

    let mut verdicts = Vec::new();
    let mut any_error = false;

    for pid in pids {
        match collect_proc_info(pid) {
            Ok(info) => {
                let (verdict, evidence) = classify(&info);
                verdicts.push(ProcessVerdict::from_info_and_verdict(&info, verdict, evidence));
            }
            Err(_) => {
                // Process may have exited between scan and collection; skip silently.
                any_error = true;
            }
        }
    }

    if let Err(e) = output::print_verdicts(&verdicts, format) {
        eprintln!("binstale: output error: {e}");
        return exit_code::ERROR;
    }

    if any_error && verdicts.is_empty() {
        return exit_code::ERROR;
    }

    let any_stale = verdicts
        .iter()
        .any(|v| v.verdict != crate::verdict::Verdict::Fresh);

    if any_stale {
        exit_code::STALE
    } else {
        exit_code::FRESH
    }
}
