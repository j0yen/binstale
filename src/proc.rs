//! `/proc` filesystem reader for binstale.
//!
//! All functions read kernel-exposed data about running processes and return
//! structured results. No I/O side-effects beyond reading `/proc`.

use std::fs;
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::error::BinstaleError;
use crate::verdict::ProcInfo;

/// Read the clock tick rate (`CLK_TCK`) from the system.
///
/// This is typically 100 Hz but may vary per kernel config.
/// On all modern Linux systems with standard `CONFIG_HZ=100`, this returns 100.
/// We cannot call `sysconf(_SC_CLK_TCK)` without `unsafe` libc bindings,
/// so we use the universal Linux user-space value.
const fn clk_tck() -> u64 {
    100_u64
}

/// Read the boot time (Unix seconds) from `/proc/stat`.
///
/// # Errors
/// Returns an error if `/proc/stat` cannot be read or does not contain `btime`.
pub(crate) fn read_btime() -> Result<u64, BinstaleError> {
    let content = fs::read_to_string("/proc/stat")
        .map_err(|e| BinstaleError::ProcRead { path: "/proc/stat".into(), source: e })?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest
                .trim()
                .parse::<u64>()
                .map_err(|_| BinstaleError::ParseError {
                    context: format!("btime value in /proc/stat: {rest}"),
                });
        }
    }

    Err(BinstaleError::ParseError {
        context: "btime line not found in /proc/stat".to_owned(),
    })
}

/// Parse the process start time (in clock ticks since boot) from `/proc/PID/stat`.
///
/// Field 22 (1-indexed) in `/proc/PID/stat` is the starttime in clock ticks.
///
/// # Errors
/// Returns an error if the file cannot be read or field 22 cannot be parsed.
pub(crate) fn read_proc_starttime_ticks(pid: u32) -> Result<u64, BinstaleError> {
    let path = format!("/proc/{pid}/stat");
    let content = fs::read_to_string(&path)
        .map_err(|e| BinstaleError::ProcRead { path: path.clone(), source: e })?;

    // The comm field (field 2) can contain spaces and parentheses. It is
    // enclosed in parens: "(comm name)". We find the last ')' to skip it.
    let after_comm = content
        .rfind(')')
        .ok_or_else(|| BinstaleError::ParseError {
            context: format!("no closing ')' in {path}"),
        })?;

    let rest = &content[after_comm + 1..];
    // Fields after comm are space-separated. Field 22 is at index 20 (0-indexed)
    // after skipping the state field (3), so offset from after_comm+1:
    // fields: state(3) ppid(4) pgrp(5) session(6) tty_nr(7) tpgid(8)
    //         flags(9) minflt(10) cminflt(11) majflt(12) cmajflt(13)
    //         utime(14) stime(15) cutime(16) cstime(17) priority(18)
    //         nice(19) num_threads(20) itrealvalue(21) starttime(22)
    // So starttime is the 20th field (0-indexed) after the closing ')'.
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // Index 19 (0-indexed) = field 22 (1-indexed relative to full stat line)
    // After ')' and space: field 3=idx0, field 4=idx1, ..., field 22=idx19
    let starttime_str = fields.get(19).ok_or_else(|| BinstaleError::ParseError {
        context: format!("field 22 (starttime) not found in {path}"),
    })?;

    starttime_str.parse::<u64>().map_err(|_| BinstaleError::ParseError {
        context: format!("starttime not numeric in {path}: {starttime_str}"),
    })
}

/// Convert process start ticks to Unix seconds using btime and `CLK_TCK`.
///
/// # Errors
/// Returns an error if btime cannot be read.
pub(crate) fn proc_start_to_secs(starttime_ticks: u64) -> Result<u64, BinstaleError> {
    let btime = read_btime()?;
    let hz = clk_tck();
    Ok(btime + starttime_ticks / hz)
}

/// Read the comm name for a process from `/proc/PID/comm`.
///
/// # Errors
/// Returns an error if the file cannot be read.
pub(crate) fn read_comm(pid: u32) -> Result<String, BinstaleError> {
    let path = format!("/proc/{pid}/comm");
    let raw = fs::read_to_string(&path)
        .map_err(|e| BinstaleError::ProcRead { path, source: e })?;
    Ok(raw.trim().to_owned())
}

/// Read the cmdline for a process from `/proc/PID/cmdline` (NUL-separated bytes).
///
/// Returns the first argument (argv[0]).
///
/// # Errors
/// Returns an error if the file cannot be read.
pub(crate) fn read_cmdline_argv0(pid: u32) -> Result<String, BinstaleError> {
    let path = format!("/proc/{pid}/cmdline");
    let raw = fs::read(&path)
        .map_err(|e| BinstaleError::ProcRead { path, source: e })?;

    // cmdline is NUL-separated; argv[0] is everything before the first NUL.
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let argv0_bytes = raw.get(..end).unwrap_or(&raw);
    Ok(String::from_utf8_lossy(argv0_bytes).into_owned())
}

/// Read the exe symlink for a process from `/proc/PID/exe`.
///
/// The kernel appends ` (deleted)` to the readlink result when the backing
/// inode has been unlinked.
///
/// # Errors
/// Returns an error if the symlink cannot be read (process may have exited).
pub(crate) fn read_exe_readlink(pid: u32) -> Result<String, BinstaleError> {
    let path = format!("/proc/{pid}/exe");
    let target = fs::read_link(&path)
        .map_err(|e| BinstaleError::ProcRead { path, source: e })?;
    Ok(target.to_string_lossy().into_owned())
}

/// Get the inode of `/proc/PID/exe` (the inode the running process uses).
///
/// # Errors
/// Returns an error if stat fails.
pub(crate) fn stat_proc_exe_inode(pid: u32) -> Result<u64, BinstaleError> {
    let path = format!("/proc/{pid}/exe");
    let meta = fs::metadata(&path)
        .map_err(|e| BinstaleError::ProcRead { path, source: e })?;
    Ok(meta.st_ino())
}

/// Get the inode and mtime of a real on-disk path.
///
/// Strips the ` (deleted)` suffix before stat-ing.
///
/// Returns `None` if the file does not exist on disk.
pub(crate) fn stat_ondisk(path_with_possible_deleted: &str) -> Option<(u64, u64)> {
    let real_path = path_with_possible_deleted
        .strip_suffix(" (deleted)")
        .unwrap_or(path_with_possible_deleted);

    let meta = fs::metadata(real_path).ok()?;
    let mtime = u64::try_from(meta.st_mtime()).unwrap_or(0);
    Some((meta.st_ino(), mtime))
}

/// Read the `user.prov.ts` xattr from an on-disk binary path.
///
/// Returns `None` gracefully when:
/// - The xattr is absent (provfs not running, or filesystem doesn't support xattrs).
/// - The value cannot be parsed as a u64 Unix timestamp.
///
/// # Errors
/// Returns an error only on unexpected xattr read failures (not `ENODATA`/`ENOTSUP`).
pub(crate) fn read_prov_ts(path: &str) -> Result<Option<u64>, BinstaleError> {
    let real_path = path.strip_suffix(" (deleted)").unwrap_or(path);

    match xattr::get(real_path, "user.prov.ts") {
        Ok(Some(bytes)) => {
            let s = String::from_utf8_lossy(&bytes);
            Ok(s.trim().parse::<u64>().ok())
        }
        Ok(None) => Ok(None),
        Err(e) => {
            // ENODATA (61) and ENOTSUP (95) are normal — xattr absent or not supported.
            // These are not BinstaleError conditions; treat as absent.
            let errno = e.raw_os_error().unwrap_or(0);
            if errno == 61 || errno == 95 {
                Ok(None)
            } else {
                Err(BinstaleError::XattrRead {
                    path: real_path.to_owned(),
                    source: e,
                })
            }
        }
    }
}

/// Collect all proc info needed for staleness classification for a given PID.
///
/// Returns `Ok(ProcInfo)` or an appropriate error (e.g., process not found → exit-2 error).
///
/// # Errors
/// Returns [`BinstaleError::ProcessNotFound`] when `/proc/PID` does not exist.
/// Returns other errors for unexpected I/O failures.
pub(crate) fn collect_proc_info(pid: u32) -> Result<ProcInfo, BinstaleError> {
    // Verify the PID exists in /proc first.
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));
    if !proc_dir.exists() {
        return Err(BinstaleError::ProcessNotFound { pid });
    }

    let comm = read_comm(pid).unwrap_or_else(|_| format!("pid-{pid}"));
    let exe_readlink = read_exe_readlink(pid)?;

    let proc_exe_inode = stat_proc_exe_inode(pid).ok();
    let ondisk = stat_ondisk(&exe_readlink);
    let ondisk_inode = ondisk.map(|(ino, _)| ino);
    let ondisk_mtime = ondisk.map(|(_, mtime)| mtime);

    let proc_start_secs = read_proc_starttime_ticks(pid)
        .and_then(proc_start_to_secs)
        .ok();

    let real_path = exe_readlink.strip_suffix(" (deleted)").unwrap_or(&exe_readlink);
    let prov_ts = read_prov_ts(real_path).unwrap_or(None);

    Ok(ProcInfo {
        pid,
        comm,
        exe_readlink,
        proc_exe_inode,
        ondisk_inode,
        proc_start_secs,
        prov_ts,
        ondisk_mtime,
    })
}

/// Scan `/proc` for all numeric PIDs that match a comm or cmdline regex.
///
/// Returns a list of PIDs whose `comm` or `argv[0]` matches the given regex.
///
/// # Errors
/// Returns an error if `/proc` cannot be read. Individual PID read failures are
/// silently skipped (processes can exit between iteration and read).
pub(crate) fn scan_matching_pids(re: &regex::Regex) -> Result<Vec<u32>, BinstaleError> {
    let mut pids = Vec::new();

    let proc_dir = Path::new("/proc");
    let entries = fs::read_dir(proc_dir).map_err(|e| BinstaleError::ProcRead {
        path: "/proc".into(),
        source: e,
    })?;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only process numeric directories (PIDs).
        if let Ok(pid) = name_str.parse::<u32>() {
            // Try comm first (fast), then argv[0] (slower).
            let comm_match = read_comm(pid).is_ok_and(|c| re.is_match(&c));
            let argv0_match = !comm_match
                && read_cmdline_argv0(pid)
                    .is_ok_and(|a| {
                        let basename = Path::new(&a)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("");
                        re.is_match(basename)
                    });

            if comm_match || argv0_match {
                pids.push(pid);
            }
        }
    }

    pids.sort_unstable();
    Ok(pids)
}
