//! `binstale` — running-binary staleness detector.
//!
//! Classifies running processes as `fresh | deleted-exe | inode-drift | prov-stale | behind-head`
//! using `/proc`, provfs xattr signals, and optional source-repository comparison.

use std::process;

use clap::{Parser, Subcommand, ValueEnum};

use binstale::error::exit_code;
use binstale::fleet::{FleetFormat, collect_fleet, print_fleet};
use binstale::output::{OutputFormat, ProcessVerdict};
use binstale::proc::{collect_proc_info, scan_matching_pids};
use binstale::source::{load_repo_map, query_source_info};
use binstale::verdict::{classify, Verdict};

/// Default daemon regex for `binstale scan` with no `--match`.
const DEFAULT_MATCH: &str = r"^(agorabus|recalld|wm-(audio|dialog|stt|tts))$";

/// Running-binary staleness detector.
///
/// Classifies running processes as:
///   fresh | deleted-exe | inode-drift | prov-stale | behind-head
///
/// Verdict taxonomy:
///   deleted-exe  — /proc/PID/exe ends in " (deleted)"; kernel unlinked the binary.
///   inode-drift  — same path, but on-disk inode changed since exec (atomic rename).
///   prov-stale   — inode matches, but provfs user.prov.ts (or mtime) is newer than process start.
///   behind-head  — binary effective build-ts predates the newest source commit touching src/.
///   fresh        — none of the above conditions detected.
///
/// Exit codes: 0=all-fresh, 1=any-stale, 2=usage/IO error
#[derive(Debug, Parser)]
#[command(
    name = "binstale",
    version = "0.3.0",
    about = "Running-binary staleness detector",
    long_about = "Classifies running processes as: fresh | deleted-exe | inode-drift | prov-stale | behind-head\n\
    \n\
    Verdict taxonomy:\n  \
      deleted-exe  — /proc/PID/exe ends in \" (deleted)\"; kernel unlinked the binary.\n  \
      inode-drift  — same path but on-disk inode changed since exec (atomic rename).\n  \
      prov-stale   — inode matches but provfs user.prov.ts (or mtime) is newer than proc start.\n  \
      behind-head  — binary effective build-ts predates the newest source commit touching src/.\n  \
      fresh        — none of the above.\n\
    \n\
    Source comparison uses a daemon→repo map from ~/.config/binstale/repos.toml\n\
    (merged over built-in fleet defaults). Use --no-source to skip git invocation.\n\
    \n\
    Exit codes: 0=all-fresh, 1=any-stale, 2=usage/IO error"
)]
struct Cli {
    /// Skip source-repository comparison (no git subprocess, no `behind-head` verdict).
    ///
    /// Use this in environments where git is unavailable or the wintermute source
    /// repos are not present. Reproduces Fleet-1 behavior exactly.
    #[arg(long, global = true)]
    no_source: bool,

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

    /// Aggregate fleet staleness report over the curated wintermute daemon list.
    ///
    /// Default targets: agorabus, recalld, wm-audio, wm-brain, wm-dialog, wm-stt, wm-tts.
    /// Use `--all` to scan every running process (expensive).
    ///
    /// Exit codes: 0=all-fresh, 1=any-stale, 2=error
    Fleet {
        /// Scan all running /proc/PID/exe entries (expensive; overrides curated list).
        #[arg(long)]
        all: bool,

        /// Output format: json (machine), human (table), docket (docket report lines).
        #[arg(long, value_enum, default_value_t = FleetFormatArg::Human)]
        format: FleetFormatArg,
    },
}

/// Output format selection for `check` / `scan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable table output.
    Table,
    /// JSON array output (one object per process).
    Json,
}

/// Output format for `fleet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FleetFormatArg {
    /// JSON array (machine-readable).
    Json,
    /// Human-readable priority-sorted table.
    Human,
    /// Ready-to-run `docket report` lines for each non-fresh daemon.
    Docket,
}

impl From<Format> for OutputFormat {
    fn from(f: Format) -> Self {
        match f {
            Format::Table => Self::Table,
            Format::Json => Self::Json,
        }
    }
}

impl From<FleetFormatArg> for FleetFormat {
    fn from(f: FleetFormatArg) -> Self {
        match f {
            FleetFormatArg::Json => FleetFormat::Json,
            FleetFormatArg::Human => FleetFormat::Human,
            FleetFormatArg::Docket => FleetFormat::Docket,
        }
    }
}

fn main() {
    // Reset SIGPIPE to default (SIG_DFL) before anything else.
    // Without this, piping to `head` or `sh` causes a panic (exit 101).
    // Per [[self_sigpipe_panic_toolkit]].
    // SAFETY: called before any threads are spawned; no signal handlers registered yet.
    #[allow(unsafe_code)]
    unsafe {
        reset_sigpipe();
    }

    let cli = Cli::parse();
    let no_source = cli.no_source;

    // Load the repo map once — shared across all PID checks in this invocation.
    // When --no-source is set, we still load the map (cheap) but query_source_info
    // will short-circuit immediately on the no_source flag.
    let repo_map = load_repo_map();

    let exit = match cli.command {
        Command::Check { pid, format } => run_check(pid, format.into(), no_source, &repo_map),
        Command::Scan { r#match: pattern, format } => {
            run_scan(&pattern, format.into(), no_source, &repo_map)
        }
        Command::Fleet { all, format } => run_fleet(all, format.into(), no_source),
    };

    process::exit(exit);
}

/// Reset SIGPIPE to default (SIG_DFL) so that pipes to `head`/`sh` exit cleanly.
///
/// Without this, the Rust runtime catches SIGPIPE and converts it to a panic,
/// producing unhelpful "broken pipe" error messages.
///
/// # Safety
/// Must be called before any threads are spawned.
#[allow(unsafe_code)]
unsafe fn reset_sigpipe() {
    unsafe extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    const SIGPIPE: i32 = 13;
    const SIG_DFL: usize = 0;
    unsafe {
        let _ = signal(SIGPIPE, SIG_DFL);
    }
}

/// Compute the effective build timestamp for a process: provfs xattr first, mtime fallback.
fn effective_build_ts(info: &binstale::verdict::ProcInfo) -> Option<u64> {
    info.prov_ts.or(info.ondisk_mtime)
}

/// Run the `check` subcommand for a single PID.
fn run_check(
    pid: u32,
    format: OutputFormat,
    no_source: bool,
    repo_map: &std::collections::HashMap<String, std::path::PathBuf>,
) -> i32 {
    match collect_proc_info(pid) {
        Err(binstale::error::BinstaleError::ProcessNotFound { pid: p }) => {
            eprintln!("binstale: process not found: PID {p}");
            exit_code::ERROR
        }
        Err(e) => {
            eprintln!("binstale: error reading /proc/{pid}: {e}");
            exit_code::ERROR
        }
        Ok(info) => {
            let build_ts = effective_build_ts(&info);
            let src_info = query_source_info(&info.comm, build_ts, repo_map, no_source);
            let (verdict, evidence) = classify(&info, src_info.behind_head);
            let pv = ProcessVerdict::from_info_and_verdict(
                &info,
                verdict.clone(),
                evidence,
                src_info.repo_path,
                src_info.head_ts,
                src_info.head_commit,
            );
            if let Err(e) = binstale::output::print_verdicts(&[pv], format) {
                eprintln!("binstale: output error: {e}");
                return exit_code::ERROR;
            }
            if verdict == Verdict::Fresh {
                exit_code::FRESH
            } else {
                exit_code::STALE
            }
        }
    }
}

/// Run the `scan` subcommand.
fn run_scan(
    pattern: &str,
    format: OutputFormat,
    no_source: bool,
    repo_map: &std::collections::HashMap<String, std::path::PathBuf>,
) -> i32 {
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
                let build_ts = effective_build_ts(&info);
                let src_info =
                    query_source_info(&info.comm, build_ts, repo_map, no_source);
                let (verdict, evidence) = classify(&info, src_info.behind_head);
                verdicts.push(ProcessVerdict::from_info_and_verdict(
                    &info,
                    verdict,
                    evidence,
                    src_info.repo_path,
                    src_info.head_ts,
                    src_info.head_commit,
                ));
            }
            Err(_) => {
                // Process may have exited between scan and collection; skip silently.
                any_error = true;
            }
        }
    }

    if let Err(e) = binstale::output::print_verdicts(&verdicts, format) {
        eprintln!("binstale: output error: {e}");
        return exit_code::ERROR;
    }

    if any_error && verdicts.is_empty() {
        return exit_code::ERROR;
    }

    let any_stale = verdicts
        .iter()
        .any(|v| v.verdict != Verdict::Fresh);

    if any_stale {
        exit_code::STALE
    } else {
        exit_code::FRESH
    }
}

/// Run the `fleet` subcommand.
fn run_fleet(all: bool, format: FleetFormat, no_source: bool) -> i32 {
    match collect_fleet(all, no_source) {
        Err(e) => {
            eprintln!("binstale: fleet scan error: {e}");
            exit_code::ERROR
        }
        Ok((entries, _had_errors)) => {
            if let Err(e) = print_fleet(&entries, format) {
                eprintln!("binstale: output error: {e}");
                return exit_code::ERROR;
            }
            let any_stale = entries
                .iter()
                .any(|e| e.verdict != Verdict::Fresh);
            if any_stale {
                exit_code::STALE
            } else {
                exit_code::FRESH
            }
        }
    }
}
