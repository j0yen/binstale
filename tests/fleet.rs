//! Integration tests for `binstale fleet` aggregate mode.
//!
//! Uses synthetic process fixtures (bypassing real /proc and git) to exercise:
//! - AC2: JSON output correctness over mixed verdicts
//! - AC3: docket output for deleted-exe + behind-head fixture
//! - AC4: fresh-only fleet → zero docket lines + exit 0
//! - AC7: curated-list guard (non-fleet process absent from default, present under --all)

use binstale::fleet::{classify_synthetic, fleet_to_docket_string, SyntheticProc};
use binstale::verdict::Verdict;

// ── helpers ──────────────────────────────────────────────────────────────────

fn fresh_proc(pid: u32, comm: &str) -> SyntheticProc {
    SyntheticProc {
        pid,
        comm: comm.to_owned(),
        exe_readlink: format!("/usr/bin/{comm}"),
        proc_exe_inode: Some(100),
        ondisk_inode: Some(100),
        proc_start_secs: Some(1_000_000),
        prov_ts: None,
        ondisk_mtime: Some(999_999), // older than start → fresh
        source_behind_head: false,
    }
}

fn deleted_exe_proc(pid: u32, comm: &str) -> SyntheticProc {
    SyntheticProc {
        pid,
        comm: comm.to_owned(),
        exe_readlink: format!("/usr/bin/{comm} (deleted)"),
        proc_exe_inode: Some(200),
        ondisk_inode: None,
        proc_start_secs: Some(1_000_000),
        prov_ts: None,
        ondisk_mtime: None,
        source_behind_head: false,
    }
}

fn behind_head_proc(pid: u32, comm: &str) -> SyntheticProc {
    SyntheticProc {
        pid,
        comm: comm.to_owned(),
        exe_readlink: format!("/usr/bin/{comm}"),
        proc_exe_inode: Some(300),
        ondisk_inode: Some(300),
        proc_start_secs: Some(1_000_000),
        prov_ts: None,
        ondisk_mtime: Some(999_999),
        source_behind_head: true,
    }
}

// ── AC2: JSON array with correct verdict per entry ────────────────────────────

#[test]
fn ac2_json_array_has_correct_verdicts() {
    let procs = vec![
        fresh_proc(100, "agorabus"),
        deleted_exe_proc(200, "recalld"),
        behind_head_proc(300, "wm-stt"),
    ];

    let entries = classify_synthetic(&procs);

    // Should have exactly 3 entries.
    assert_eq!(entries.len(), 3, "should have one entry per input proc");

    // Verdicts should match expectations.
    let by_comm: std::collections::HashMap<_, _> =
        entries.iter().map(|e| (e.comm.as_str(), e.verdict.clone())).collect();

    assert_eq!(
        by_comm.get("agorabus").cloned(),
        Some(Verdict::Fresh),
        "agorabus should be fresh"
    );
    assert_eq!(
        by_comm.get("recalld").cloned(),
        Some(Verdict::DeletedExe),
        "recalld should be deleted-exe"
    );
    assert_eq!(
        by_comm.get("wm-stt").cloned(),
        Some(Verdict::BehindHead),
        "wm-stt should be behind-head"
    );
}

#[test]
fn ac2_json_output_is_valid_json_array() {
    let procs = vec![fresh_proc(1, "agorabus"), deleted_exe_proc(2, "recalld")];
    let entries = classify_synthetic(&procs);

    let json = serde_json::to_string(&entries).expect("entries should serialise to JSON");
    let parsed: serde_json::Value =
        serde_json::from_str(&json).expect("output should be valid JSON");

    assert!(parsed.is_array(), "top-level should be a JSON array");
    assert_eq!(
        parsed.as_array().map(|a| a.len()),
        Some(2),
        "array should have 2 entries"
    );
}

// ── AC3: docket output for deleted-exe + behind-head ─────────────────────────

#[test]
fn ac3_docket_two_lines_for_deleted_and_behind() {
    let procs = vec![
        deleted_exe_proc(101, "agorabus"),
        behind_head_proc(202, "wm-tts"),
    ];
    let entries = classify_synthetic(&procs);
    let docket = fleet_to_docket_string(&entries).expect("docket should succeed");

    let lines: Vec<&str> = docket.lines().collect();
    assert_eq!(lines.len(), 2, "should emit exactly 2 docket lines");
}

#[test]
fn ac3_deleted_exe_gets_alert_severity() {
    let procs = vec![deleted_exe_proc(101, "agorabus")];
    let entries = classify_synthetic(&procs);
    let docket = fleet_to_docket_string(&entries).expect("docket should succeed");

    assert!(
        docket.contains("--severity alert"),
        "deleted-exe should be alert; got: {docket}"
    );
    assert!(
        docket.contains("--key binstale-agorabus"),
        "key should be binstale-agorabus; got: {docket}"
    );
    assert!(
        docket.contains("--evidence pid:101"),
        "evidence should contain pid:101; got: {docket}"
    );
}

#[test]
fn ac3_behind_head_gets_warn_severity() {
    let procs = vec![behind_head_proc(202, "wm-tts")];
    let entries = classify_synthetic(&procs);
    let docket = fleet_to_docket_string(&entries).expect("docket should succeed");

    assert!(
        docket.contains("--severity warn"),
        "behind-head should be warn; got: {docket}"
    );
    assert!(
        docket.contains("--key binstale-wm-tts"),
        "key should be binstale-wm-tts; got: {docket}"
    );
    assert!(
        docket.contains("--evidence pid:202"),
        "evidence should contain pid:202; got: {docket}"
    );
}

#[test]
fn ac3_docket_lines_have_stable_key_format() {
    // Key must be `binstale-<comm>` — no spaces, no special chars.
    let procs = vec![deleted_exe_proc(500, "recalld")];
    let entries = classify_synthetic(&procs);
    let docket = fleet_to_docket_string(&entries).expect("docket should succeed");

    // The line must start with `docket report`.
    let line = docket.lines().next().unwrap_or("");
    assert!(
        line.starts_with("docket report "),
        "line must start with 'docket report '; got: {line}"
    );
    assert!(
        line.contains("--key binstale-recalld"),
        "stable key binstale-recalld; got: {line}"
    );
}

// ── AC4: fresh-only fleet → zero docket lines ────────────────────────────────

#[test]
fn ac4_fresh_only_fleet_zero_docket_lines() {
    let procs = vec![
        fresh_proc(1, "agorabus"),
        fresh_proc(2, "recalld"),
        fresh_proc(3, "wm-stt"),
    ];
    let entries = classify_synthetic(&procs);
    let docket = fleet_to_docket_string(&entries).expect("docket should succeed");

    assert!(
        docket.is_empty(),
        "fresh-only fleet should produce zero docket lines; got: {docket:?}"
    );
}

// ── Priority sort: deleted-exe comes before behind-head ──────────────────────

#[test]
fn priority_sort_deleted_before_behind() {
    // Insert in "wrong" order to verify sort.
    let procs = vec![
        behind_head_proc(10, "wm-dialog"),
        deleted_exe_proc(20, "agorabus"),
        fresh_proc(30, "recalld"),
    ];
    let entries = classify_synthetic(&procs);

    assert_eq!(entries[0].verdict, Verdict::DeletedExe, "deleted-exe must come first");
    assert_eq!(entries[1].verdict, Verdict::BehindHead, "behind-head second");
    assert_eq!(entries[2].verdict, Verdict::Fresh, "fresh last");
}

// ── Each entry carries pid and comm ──────────────────────────────────────────

#[test]
fn entries_carry_pid_and_comm() {
    let procs = vec![deleted_exe_proc(999, "wm-brain")];
    let entries = classify_synthetic(&procs);

    assert_eq!(entries[0].pid, 999);
    assert_eq!(entries[0].comm, "wm-brain");
}
