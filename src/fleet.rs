//! Fleet aggregate mode for `binstale fleet`.
//!
//! Checks a curated list of wintermute daemon processes plus mapped
//! `~/.local/bin/*` tools, returning a [`FleetEntry`] per target.
//! With `--all`, scans all running `/proc/PID/exe` entries instead.

use serde::{Deserialize, Serialize};

use crate::output::ProcessVerdict;
use crate::proc::{collect_proc_info, scan_matching_pids};
use crate::source::{load_repo_map, query_source_info};
use crate::verdict::{classify, Verdict};

/// Default curated fleet regex: the six wintermute daemon comm names.
pub const FLEET_MATCH: &str =
    r"^(agorabus|recalld|wm-audio|wm-brain|wm-dialog|wm-stt|wm-tts)$";

/// Output format for `binstale fleet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetFormat {
    /// JSON array of [`ProcessVerdict`] objects (machine-readable).
    Json,
    /// Human-readable priority-sorted table.
    Human,
    /// `docket report` shell lines for each non-fresh daemon.
    Docket,
}

/// A single entry in the fleet report, re-exported for test access.
pub type FleetEntry = ProcessVerdict;

/// Collect fleet verdicts.
///
/// When `all` is `true`, all running processes are scanned.
/// Otherwise only the curated daemon list is matched.
///
/// `no_source` suppresses git source comparison (no `behind-head` verdict).
///
/// Returns `(Vec<FleetEntry>, had_errors)` — errors are per-PID read
/// failures that are logged to stderr and skipped (process may have exited).
///
/// # Errors
/// Returns an error only if `/proc` itself is unreadable.
pub fn collect_fleet(
    all: bool,
    no_source: bool,
) -> Result<(Vec<FleetEntry>, bool), Box<dyn std::error::Error>> {
    let repo_map = load_repo_map();
    let pattern = if all { r"." } else { FLEET_MATCH };

    let re = regex::Regex::new(pattern)?;
    let pids = scan_matching_pids(&re)?;

    let mut entries: Vec<FleetEntry> = Vec::new();
    let mut had_errors = false;

    for pid in pids {
        match collect_proc_info(pid) {
            Ok(info) => {
                let build_ts = info.prov_ts.or(info.ondisk_mtime);
                let src_info = query_source_info(&info.comm, build_ts, &repo_map, no_source);
                let (verdict, evidence) = classify(&info, src_info.behind_head);
                entries.push(ProcessVerdict::from_info_and_verdict(
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
                had_errors = true;
            }
        }
    }

    // Priority sort: deleted-exe > inode-drift > prov-stale > behind-head > fresh
    entries.sort_by_key(|e| verdict_priority(&e.verdict));

    Ok((entries, had_errors))
}

/// Priority rank for sorting: lower = shown first (higher severity).
fn verdict_priority(v: &Verdict) -> u8 {
    match v {
        Verdict::DeletedExe => 0,
        Verdict::InodeDrift => 1,
        Verdict::ProvStale => 2,
        Verdict::BehindHead => 3,
        Verdict::Fresh => 4,
    }
}

/// Print fleet output in the requested format.
///
/// # Errors
/// Returns an error if JSON serialisation or I/O fails.
pub fn print_fleet(
    entries: &[FleetEntry],
    format: FleetFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    match format {
        FleetFormat::Json => {
            let json = serde_json::to_string_pretty(entries)?;
            writeln!(out, "{json}")?;
        }
        FleetFormat::Human => {
            print_human(&mut out, entries)?;
        }
        FleetFormat::Docket => {
            print_docket(&mut out, entries)?;
        }
    }
    Ok(())
}

/// Emit a human-readable priority-sorted table.
fn print_human(
    out: &mut impl std::io::Write,
    entries: &[FleetEntry],
) -> Result<(), std::io::Error> {
    if entries.is_empty() {
        writeln!(out, "No fleet processes found.")?;
        return Ok(());
    }
    writeln!(
        out,
        "{:<8}  {:<20}  {:<12}  {:<}",
        "PID", "COMM", "VERDICT", "EXE"
    )?;
    writeln!(out, "{}", "-".repeat(72))?;
    for e in entries {
        let comm = if e.comm.len() <= 20 {
            e.comm.clone()
        } else {
            format!("{}…", &e.comm[..19])
        };
        writeln!(
            out,
            "{:<8}  {:<20}  {:<12}  {}",
            e.pid, comm, e.verdict, e.exe_path
        )?;
    }
    Ok(())
}

/// Emit ready-to-run `docket report` shell lines for each non-fresh entry.
///
/// Format:
/// ```text
/// docket report --key binstale-<comm> --severity <alert|warn> \
///   --title "<verdict>: <comm> (pid <pid>)" --evidence pid:<pid>
/// ```
/// alert: deleted-exe, inode-drift
/// warn:  prov-stale, behind-head
fn print_docket(
    out: &mut impl std::io::Write,
    entries: &[FleetEntry],
) -> Result<(), std::io::Error> {
    for e in entries {
        if e.verdict == Verdict::Fresh {
            continue;
        }
        let severity = match e.verdict {
            Verdict::DeletedExe | Verdict::InodeDrift => "alert",
            _ => "warn",
        };
        let key = format!("binstale-{}", e.comm);
        let title = format!("{}: {} (pid {})", e.verdict, e.comm, e.pid);
        writeln!(
            out,
            "docket report --key {key} --severity {severity} --title \"{title}\" --evidence pid:{pid}",
            pid = e.pid
        )?;
    }
    Ok(())
}

// ── synthetic fixture helpers (used by integration tests) ────────────────────

/// A synthetic process descriptor for testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticProc {
    /// PID (synthetic; does not correspond to a real process).
    pub pid: u32,
    /// Process comm name.
    pub comm: String,
    /// Resolved exe path.
    pub exe_readlink: String,
    /// proc_exe_inode.
    pub proc_exe_inode: Option<u64>,
    /// ondisk_inode.
    pub ondisk_inode: Option<u64>,
    /// proc_start_secs.
    pub proc_start_secs: Option<u64>,
    /// prov_ts.
    pub prov_ts: Option<u64>,
    /// ondisk_mtime.
    pub ondisk_mtime: Option<u64>,
    /// source_behind_head (injected directly, skipping git).
    pub source_behind_head: bool,
}

/// Classify a slice of synthetic process descriptors and return fleet entries.
///
/// This is the testable path that bypasses all real `/proc` and `git` I/O.
#[must_use]
pub fn classify_synthetic(procs: &[SyntheticProc]) -> Vec<FleetEntry> {
    use crate::verdict::ProcInfo;

    let mut entries: Vec<FleetEntry> = procs
        .iter()
        .map(|sp| {
            let info = ProcInfo {
                pid: sp.pid,
                comm: sp.comm.clone(),
                exe_readlink: sp.exe_readlink.clone(),
                proc_exe_inode: sp.proc_exe_inode,
                ondisk_inode: sp.ondisk_inode,
                proc_start_secs: sp.proc_start_secs,
                prov_ts: sp.prov_ts,
                ondisk_mtime: sp.ondisk_mtime,
            };
            let (verdict, evidence) = classify(&info, sp.source_behind_head);
            ProcessVerdict::from_info_and_verdict(
                &info,
                verdict,
                evidence,
                None,
                None,
                None,
            )
        })
        .collect();

    entries.sort_by_key(|e| verdict_priority(&e.verdict));
    entries
}

/// Render fleet entries as a docket string (for testing).
///
/// # Errors
/// Returns an error if writing to the internal buffer fails.
pub fn fleet_to_docket_string(
    entries: &[FleetEntry],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut buf: Vec<u8> = Vec::new();
    print_docket(&mut buf, entries)?;
    Ok(String::from_utf8(buf)?)
}
