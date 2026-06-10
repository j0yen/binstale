//! Verdict classification for running-binary staleness detection.
//!
//! The [`Verdict`] enum and [`classify`] function are pure functions over
//! [`ProcInfo`] structs — no filesystem I/O here, which makes them
//! independently unit-testable.

use serde::{Deserialize, Serialize};

/// Staleness verdict for a running process's binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// The `/proc/PID/exe` symlink target ends in the kernel's ` (deleted)`
    /// marker. The backing inode has been unlinked. Highest confidence.
    DeletedExe,
    /// The exe symlink resolves to a real path, but that path's current inode
    /// (`stat(resolved_path).st_ino`) differs from the inode the process is
    /// running (`stat(/proc/PID/exe).st_ino`). Atomic rename replaced the file.
    InodeDrift,
    /// exe and on-disk inode match, but the on-disk binary's `user.prov.ts`
    /// xattr (or mtime when xattr absent) is newer than the process start time.
    /// The file was reinstalled after this process started.
    ProvStale,
    /// Binary's effective build timestamp predates the newest source commit
    /// touching `src/`. A fix has been committed but not yet rebuilt/installed.
    /// Ranks below file-level verdicts; recorded in `evidence` when those win.
    BehindHead,
    /// None of the above staleness conditions detected.
    Fresh,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeletedExe => write!(f, "deleted-exe"),
            Self::InodeDrift => write!(f, "inode-drift"),
            Self::ProvStale => write!(f, "prov-stale"),
            Self::BehindHead => write!(f, "behind-head"),
            Self::Fresh => write!(f, "fresh"),
        }
    }
}

/// Evidence collected during classification.
// The boolean fields are distinct binary signals — each represents an
// independent kernel observation. A state-machine or enum would obscure
// that they can fire in combination (e.g., deleted-exe AND behind-head).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// True if the exe readlink ends in ` (deleted)`.
    pub exe_deleted_suffix: bool,
    /// True if the running inode differs from the on-disk inode.
    pub inode_mismatch: bool,
    /// True if the provfs/mtime timestamp is newer than process start.
    pub timestamp_newer: bool,
    /// How the timestamp was determined.
    pub timestamp_source: TimestampSource,
    /// True if the binary's build timestamp predates the newest source commit.
    /// Recorded even when a file-level verdict wins (see `behind_head` in output).
    pub behind_head: bool,
}

/// How the on-disk binary's modification time was determined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimestampSource {
    /// `user.prov.ts` xattr was present and used.
    ProvXattr,
    /// xattr absent; on-disk mtime used as fallback.
    MtimeFallback,
    /// Neither xattr nor mtime was available (e.g., path not resolvable).
    Unavailable,
}

/// All information about a running process needed for classification.
/// Fields are the raw kernel observations; `classify()` is the pure decision function.
#[derive(Debug, Clone)]
pub struct ProcInfo {
    /// PID of the process.
    pub pid: u32,
    /// Process comm name (from `/proc/PID/comm`).
    pub comm: String,
    /// Resolved exe path (from `readlink /proc/PID/exe`).
    /// May end in ` (deleted)` if the backing inode is unlinked.
    pub exe_readlink: String,
    /// Inode the process is running (from `stat(/proc/PID/exe)`).
    /// None if the stat failed (e.g., process exited between readlink and stat).
    pub proc_exe_inode: Option<u64>,
    /// Current on-disk inode of the resolved path (stripping ` (deleted)` suffix).
    /// None if the file is not accessible on disk.
    pub ondisk_inode: Option<u64>,
    /// Process start time as a Unix timestamp (seconds).
    /// Derived from `/proc/PID/stat` field 22 + `/proc/stat btime` + `sysconf(CLK_TCK)`.
    pub proc_start_secs: Option<u64>,
    /// On-disk binary's `user.prov.ts` xattr value (Unix seconds string), if present.
    pub prov_ts: Option<u64>,
    /// On-disk binary's mtime (Unix seconds), used when `prov_ts` is absent.
    pub ondisk_mtime: Option<u64>,
}

/// Classify a process's binary staleness from its pre-collected [`ProcInfo`].
///
/// `source_behind_head` is the result of the source-vs-binary comparison from
/// [`crate::source::query_source_info`]. Pass `false` when `--no-source` is set
/// or no repo mapping exists.
///
/// This is a pure function — no I/O. All observations must be pre-collected
/// by [`crate::proc::collect_proc_info`].
///
/// # Returns
/// A `(Verdict, Evidence)` pair. The evidence records which signals fired.
/// When a file-level verdict (deleted-exe / inode-drift / prov-stale) wins,
/// `behind_head` is still recorded in the evidence if it fired.
#[must_use]
pub fn classify(info: &ProcInfo, source_behind_head: bool) -> (Verdict, Evidence) {
    // Step 1: Check for kernel's (deleted) suffix — unambiguous.
    let exe_deleted = info.exe_readlink.ends_with(" (deleted)");

    // Step 2: Check inode drift — both inodes must be available.
    let inode_mismatch = match (info.proc_exe_inode, info.ondisk_inode) {
        (Some(proc_ino), Some(disk_ino)) => proc_ino != disk_ino,
        _ => false,
    };

    // Step 3: Check timestamp staleness.
    let (timestamp_newer, timestamp_source) = if exe_deleted || inode_mismatch {
        // Already stale via stronger signals; skip timestamp check.
        (false, TimestampSource::Unavailable)
    } else {
        match (info.proc_start_secs, info.prov_ts, info.ondisk_mtime) {
            (Some(start), Some(prov), _) => (prov > start, TimestampSource::ProvXattr),
            (Some(start), None, Some(mtime)) => (mtime > start, TimestampSource::MtimeFallback),
            _ => (false, TimestampSource::Unavailable),
        }
    };

    // Step 4: Select primary verdict. File-level verdicts outrank behind-head.
    // behind-head is always recorded in evidence even when it doesn't win.
    let verdict = if exe_deleted {
        Verdict::DeletedExe
    } else if inode_mismatch {
        Verdict::InodeDrift
    } else if timestamp_newer {
        Verdict::ProvStale
    } else if source_behind_head {
        Verdict::BehindHead
    } else {
        Verdict::Fresh
    };

    let evidence = Evidence {
        exe_deleted_suffix: exe_deleted,
        inode_mismatch,
        timestamp_newer,
        timestamp_source,
        behind_head: source_behind_head,
    };

    (verdict, evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_info() -> ProcInfo {
        ProcInfo {
            pid: 1234,
            comm: "test-proc".to_owned(),
            exe_readlink: "/tmp/test-binary".to_owned(),
            proc_exe_inode: Some(100),
            ondisk_inode: Some(100),
            proc_start_secs: Some(1_000_000),
            prov_ts: None,
            ondisk_mtime: Some(999_999),
        }
    }

    #[test]
    fn fresh_verdict_all_match() {
        let info = base_info();
        let (verdict, ev) = classify(&info, false);
        assert_eq!(verdict, Verdict::Fresh);
        assert!(!ev.exe_deleted_suffix);
        assert!(!ev.inode_mismatch);
        assert!(!ev.timestamp_newer);
        assert!(!ev.behind_head);
    }

    #[test]
    fn deleted_exe_verdict() {
        let mut info = base_info();
        info.exe_readlink = "/tmp/test-binary (deleted)".to_owned();
        let (verdict, ev) = classify(&info, false);
        assert_eq!(verdict, Verdict::DeletedExe);
        assert!(ev.exe_deleted_suffix);
    }

    #[test]
    fn inode_drift_verdict() {
        let mut info = base_info();
        info.ondisk_inode = Some(200); // differs from proc_exe_inode=100
        let (verdict, ev) = classify(&info, false);
        assert_eq!(verdict, Verdict::InodeDrift);
        assert!(ev.inode_mismatch);
    }

    #[test]
    fn prov_stale_via_xattr() {
        let mut info = base_info();
        info.prov_ts = Some(1_000_001); // reinstalled after process started at 1_000_000
        let (verdict, ev) = classify(&info, false);
        assert_eq!(verdict, Verdict::ProvStale);
        assert!(ev.timestamp_newer);
        assert_eq!(ev.timestamp_source, TimestampSource::ProvXattr);
    }

    #[test]
    fn prov_stale_via_mtime_fallback() {
        let mut info = base_info();
        info.ondisk_mtime = Some(1_000_001); // mtime newer than proc start
        let (verdict, ev) = classify(&info, false);
        assert_eq!(verdict, Verdict::ProvStale);
        assert!(ev.timestamp_newer);
        assert_eq!(ev.timestamp_source, TimestampSource::MtimeFallback);
    }

    #[test]
    fn fresh_when_xattr_absent_and_mtime_older() {
        let mut info = base_info();
        info.prov_ts = None;
        info.ondisk_mtime = Some(999_999); // older than proc start
        let (verdict, _) = classify(&info, false);
        assert_eq!(verdict, Verdict::Fresh);
    }

    #[test]
    fn deleted_takes_priority_over_inode_drift() {
        let mut info = base_info();
        info.exe_readlink = "/tmp/test-binary (deleted)".to_owned();
        info.ondisk_inode = Some(200); // would be inode-drift too
        let (verdict, _) = classify(&info, false);
        assert_eq!(verdict, Verdict::DeletedExe);
    }

    #[test]
    fn missing_inodes_not_inode_drift() {
        let mut info = base_info();
        info.proc_exe_inode = None; // stat failed
        let (verdict, ev) = classify(&info, false);
        assert!(!ev.inode_mismatch);
        assert_eq!(verdict, Verdict::Fresh); // can't determine drift, default fresh
    }

    #[test]
    fn behind_head_verdict_when_source_newer() {
        let info = base_info(); // fresh file-level signals
        let (verdict, ev) = classify(&info, true);
        assert_eq!(verdict, Verdict::BehindHead);
        assert!(ev.behind_head);
    }

    #[test]
    fn file_level_verdict_wins_over_behind_head() {
        // deleted-exe should win even when behind_head is also true
        let mut info = base_info();
        info.exe_readlink = "/tmp/test-binary (deleted)".to_owned();
        let (verdict, ev) = classify(&info, true);
        assert_eq!(verdict, Verdict::DeletedExe, "file-level must outrank behind-head");
        // behind_head is still recorded in evidence
        assert!(ev.behind_head, "behind_head recorded in evidence even when outranked");
    }
}
