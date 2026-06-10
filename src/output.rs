//! Output formatting for binstale verdicts.
//!
//! Supports two formats: `table` (human-readable) and `json` (machine-readable).

use std::io::{self, Write as _};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::verdict::{Evidence, ProcInfo, Verdict};

/// A single process's verdict result, ready for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessVerdict {
    /// Process ID.
    pub pid: u32,
    /// Process comm name.
    pub comm: String,
    /// Resolved exe path (may end in ` (deleted)`).
    pub exe_path: String,
    /// Inode the process is running (from `/proc/PID/exe`).
    pub exe_inode: Option<u64>,
    /// Current on-disk inode.
    pub ondisk_inode: Option<u64>,
    /// `user.prov.ts` xattr value, if present.
    pub prov_ts: Option<u64>,
    /// Process start time (Unix seconds).
    pub proc_start: Option<u64>,
    /// Staleness verdict.
    pub verdict: Verdict,
    /// Evidence details supporting the verdict.
    pub evidence: Evidence,
    /// Path to the mapped source repository (`null` when no mapping or `--no-source`).
    pub source_repo: Option<PathBuf>,
    /// Timestamp (Unix seconds) of the newest commit touching `src/` (`null` when unavailable).
    pub source_head_ts: Option<u64>,
    /// Short SHA of the newest `src/` commit (`null` when unavailable).
    pub source_head_commit: Option<String>,
}

impl ProcessVerdict {
    /// Build a `ProcessVerdict` from a collected [`ProcInfo`] and classified verdict.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn from_info_and_verdict(
        info: &ProcInfo,
        verdict: Verdict,
        evidence: Evidence,
        source_repo: Option<PathBuf>,
        source_head_ts: Option<u64>,
        source_head_commit: Option<String>,
    ) -> Self {
        Self {
            pid: info.pid,
            comm: info.comm.clone(),
            exe_path: info.exe_readlink.clone(),
            exe_inode: info.proc_exe_inode,
            ondisk_inode: info.ondisk_inode,
            prov_ts: info.prov_ts,
            proc_start: info.proc_start_secs,
            verdict,
            evidence,
            source_repo,
            source_head_ts,
            source_head_commit,
        }
    }
}

/// Output format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable table.
    Table,
    /// JSON (one object per line, or a JSON array).
    Json,
}

/// Print a list of `ProcessVerdict`s in the specified format.
///
/// For `json`, emits a JSON array of objects to stdout.
/// For `table`, emits a header row then one row per process.
///
/// # Errors
/// Returns an error if JSON serialization or I/O fails.
pub fn print_verdicts(
    verdicts: &[ProcessVerdict],
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(verdicts)?;
            writeln!(out, "{json}")?;
        }
        OutputFormat::Table => {
            print_table(&mut out, verdicts)?;
        }
    }
    Ok(())
}

/// Print verdicts as a human-readable table.
///
/// # Errors
/// Returns an error if writing to the output fails.
fn print_table(
    out: &mut impl io::Write,
    verdicts: &[ProcessVerdict],
) -> Result<(), io::Error> {
    if verdicts.is_empty() {
        writeln!(out, "No matching processes found.")?;
        return Ok(());
    }

    // Header
    writeln!(
        out,
        "{:<8}  {:<20}  {:<12}  {:<}",
        "PID", "COMM", "VERDICT", "EXE"
    )?;
    writeln!(out, "{}", "-".repeat(72))?;

    for v in verdicts {
        writeln!(
            out,
            "{:<8}  {:<20}  {:<12}  {}",
            v.pid,
            truncate(&v.comm, 20),
            v.verdict,
            v.exe_path
        )?;
    }
    Ok(())
}

/// Truncate a string to `max_len` chars, appending `…` if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_owned()
    } else {
        format!("{}…", &s[..max_len.saturating_sub(1)])
    }
}
