//! Source-repository comparison for the `behind-head` verdict.
//!
//! Maps a daemon name to its source repository and compares the binary's
//! effective build timestamp against the newest commit touching `src/`.
//!
//! Config file: `~/.config/binstale/repos.toml`
//! Format:
//! ```toml
//! [repos]
//! agorabus  = "/home/user/wintermute/agorabus"
//! recalld   = "/home/user/wintermute/recall"
//! ```
//!
//! Built-in defaults map the known wintermute fleet; user config merges over them.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

// ── built-in defaults ───────────────────────────────────────────────────────

/// Built-in daemon→repo mappings for the wintermute fleet.
/// Keys are daemon `comm` names; values are relative paths under `$HOME`.
const BUILTIN_REPOS: &[(&str, &str)] = &[
    ("agorabus",  "wintermute/agorabus"),
    ("recalld",   "wintermute/recall"),
    ("wm-audio",  "wintermute/wintermute-audio"),
    ("wm-dialog", "wintermute/wintermute-dialog"),
    ("wm-stt",    "wintermute/wintermute-stt"),
    ("wm-tts",    "wintermute/wintermute-tts"),
    ("binstale",  "wintermute/binstale"),
];

// ── TOML config shape ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct ReposConfig {
    #[serde(default)]
    repos: HashMap<String, String>,
}

// ── public API ───────────────────────────────────────────────────────────────

/// The outcome of a source-vs-binary comparison.
#[derive(Debug, Clone)]
pub struct SourceInfo {
    /// Absolute path to the mapped source repository, if any.
    pub repo_path: Option<PathBuf>,
    /// Timestamp (Unix seconds) of the newest commit touching `src/` in the repo.
    pub head_ts: Option<u64>,
    /// Short SHA of that commit (7 chars).
    pub head_commit: Option<String>,
    /// True if the binary's effective build timestamp predates `head_ts`.
    pub behind_head: bool,
}

/// Build the effective daemon→repo map by merging built-ins with user config.
///
/// User config wins when the same daemon name appears in both.
///
/// Never errors — missing config is silently treated as empty.
pub fn load_repo_map() -> HashMap<String, PathBuf> {
    let home = home_dir();
    let mut map: HashMap<String, PathBuf> = HashMap::new();

    // Seed with built-ins (resolved relative to $HOME).
    if let Some(ref h) = home {
        for &(daemon, rel) in BUILTIN_REPOS {
            map.insert(daemon.to_owned(), h.join(rel));
        }
    }

    // Overlay user config.
    if let Some(cfg) = config_file_path() {
        if cfg.exists() {
            if let Ok(text) = std::fs::read_to_string(&cfg) {
                if let Ok(parsed) = toml::from_str::<ReposConfig>(&text) {
                    for (k, v) in parsed.repos {
                        map.insert(k, PathBuf::from(v));
                    }
                }
            }
        }
    }

    map
}

/// Query source repository information for a daemon by comm name.
///
/// Returns a [`SourceInfo`] with all fields populated if a repo mapping exists
/// and `git` is available. Degrades gracefully on any failure — fields are
/// `None` and `behind_head` is `false`.
///
/// `binary_build_ts` is the effective build timestamp of the running binary
/// (provfs `user.prov.ts` if present, otherwise binary mtime).
pub fn query_source_info(
    comm: &str,
    binary_build_ts: Option<u64>,
    repo_map: &HashMap<String, PathBuf>,
    no_source: bool,
) -> SourceInfo {
    if no_source {
        return SourceInfo {
            repo_path: None,
            head_ts: None,
            head_commit: None,
            behind_head: false,
        };
    }

    let repo_path = match repo_map.get(comm) {
        Some(p) => p.clone(),
        None => {
            return SourceInfo {
                repo_path: None,
                head_ts: None,
                head_commit: None,
                behind_head: false,
            };
        }
    };

    if !repo_path.exists() {
        eprintln!(
            "binstale: source repo for '{comm}' not found at {}: skipping source comparison",
            repo_path.display()
        );
        return SourceInfo {
            repo_path: Some(repo_path),
            head_ts: None,
            head_commit: None,
            behind_head: false,
        };
    }

    let (head_ts, head_commit) = git_head_src_ts(&repo_path);

    let behind_head = match (binary_build_ts, head_ts) {
        (Some(build), Some(head)) => build < head,
        _ => false,
    };

    SourceInfo {
        repo_path: Some(repo_path),
        head_ts,
        head_commit,
        behind_head,
    }
}

// ── private helpers ──────────────────────────────────────────────────────────

/// Run `git log -1 --format=%ct<TAB>%h -- src/` in the given repo.
///
/// Returns `(timestamp, short_sha)` on success. Returns `(None, None)` on any
/// failure (git not on PATH, not a git repo, no src/ commits, etc.).
fn git_head_src_ts(repo: &Path) -> (Option<u64>, Option<String>) {
    let output = match Command::new("git")
        .args([
            "-C",
            &repo.to_string_lossy(),
            "log",
            "-1",
            "--format=%ct\t%h",
            "--",
            "src/",
        ])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                eprintln!("binstale: 'git' not found on PATH; source comparison unavailable");
            } else {
                eprintln!(
                    "binstale: git invocation failed for {}: {e}",
                    repo.display()
                );
            }
            return (None, None);
        }
    };

    if !output.status.success() {
        eprintln!(
            "binstale: git log failed for {} (exit {})",
            repo.display(),
            output.status
        );
        return (None, None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim();
    if line.is_empty() {
        // No commits touching src/ — not an error, just no data.
        return (None, None);
    }

    let mut parts = line.splitn(2, '\t');
    let ts_str = parts.next().unwrap_or("");
    let sha = parts.next().unwrap_or("").to_owned();

    let ts = ts_str.trim().parse::<u64>().ok();
    if ts.is_none() {
        eprintln!("binstale: could not parse git timestamp from '{line}'");
    }

    (ts, if sha.is_empty() { None } else { Some(sha) })
}

/// Return the path to the user config file `~/.config/binstale/repos.toml`.
fn config_file_path() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".config/binstale/repos.toml"))
}

/// Get `$HOME` as a `PathBuf`.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal fake git repo with one commit touching src/foo.rs,
    /// with the commit timestamp set to `src_ts`.
    fn make_fake_repo(dir: &Path, src_ts: u64) -> PathBuf {
        let repo = dir.join("fake-repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();

        let repo_str = repo.to_string_lossy().into_owned();

        // Init git repo.
        Command::new("git")
            .args(["-C", &repo_str, "init"])
            .output()
            .unwrap();

        // Configure identity and default branch.
        for args in [
            vec!["-C", &repo_str, "config", "user.email", "t@t.com"],
            vec!["-C", &repo_str, "config", "user.name", "T"],
            vec!["-C", &repo_str, "config", "init.defaultBranch", "main"],
        ] {
            Command::new("git").args(&args).output().unwrap();
        }

        // Write src/foo.rs.
        std::fs::write(repo.join("src/foo.rs"), "fn main() {}").unwrap();

        Command::new("git")
            .args(["-C", &repo_str, "add", "src/foo.rs"])
            .output()
            .unwrap();

        // Commit with a specific committer/author date so %ct is predictable.
        // Git accepts "@<unix-timestamp> <tz>" as an internal date format.
        let ts_iso = format!("@{src_ts} +0000");
        Command::new("git")
            .args([
                "-C",
                &repo_str,
                "commit",
                "--date",
                &ts_iso,
                "-m",
                "initial",
            ])
            .env("GIT_COMMITTER_DATE", &ts_iso)
            .output()
            .unwrap();

        repo
    }

    #[test]
    fn behind_head_when_binary_predates_commit() {
        let tmp = tempfile::tempdir().unwrap();
        // Commit timestamp: 2_000_000; binary build: 1_800_000 (predates)
        let repo = make_fake_repo(tmp.path(), 2_000_000);
        let mut map = HashMap::new();
        map.insert("myapp".to_owned(), repo);

        let info = query_source_info("myapp", Some(1_800_000), &map, false);
        assert_eq!(info.head_ts, Some(2_000_000), "head_ts should match commit");
        assert!(info.behind_head, "should be behind-head");
        assert!(info.head_commit.is_some(), "commit sha should be present");
    }

    #[test]
    fn fresh_when_binary_newer_than_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = make_fake_repo(tmp.path(), 2_000_000);
        let mut map = HashMap::new();
        map.insert("myapp".to_owned(), repo);

        let info = query_source_info("myapp", Some(2_100_000), &map, false);
        assert_eq!(info.head_ts, Some(2_000_000));
        assert!(!info.behind_head, "should be fresh (binary newer than commit)");
    }

    #[test]
    fn no_mapping_returns_nulls() {
        let map: HashMap<String, PathBuf> = HashMap::new();
        let info = query_source_info("unknown-daemon", Some(1_000_000), &map, false);
        assert!(info.repo_path.is_none());
        assert!(info.head_ts.is_none());
        assert!(!info.behind_head);
    }

    #[test]
    fn no_source_flag_skips_git() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = make_fake_repo(tmp.path(), 2_000_000);
        let mut map = HashMap::new();
        map.insert("myapp".to_owned(), repo);

        let info = query_source_info("myapp", Some(1_800_000), &map, true);
        assert!(info.repo_path.is_none());
        assert!(info.head_ts.is_none());
        assert!(!info.behind_head, "--no-source must suppress git");
    }

    #[test]
    fn missing_repo_path_degrades_gracefully() {
        let mut map = HashMap::new();
        map.insert(
            "myapp".to_owned(),
            PathBuf::from("/nonexistent/path/to/repo"),
        );

        let info = query_source_info("myapp", Some(1_000_000), &map, false);
        // repo_path is set but head_ts is None (graceful degradation)
        assert!(info.repo_path.is_some());
        assert!(info.head_ts.is_none());
        assert!(!info.behind_head);
    }

    #[test]
    fn no_binary_ts_not_behind_head() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = make_fake_repo(tmp.path(), 2_000_000);
        let mut map = HashMap::new();
        map.insert("myapp".to_owned(), repo);

        // binary_build_ts = None (unknown)
        let info = query_source_info("myapp", None, &map, false);
        assert!(!info.behind_head, "unknown build ts → not behind-head (conservative)");
    }

    #[test]
    fn load_repo_map_has_builtin_agorabus() {
        // Just verify the built-ins parse; don't assert on file existence.
        let map = load_repo_map();
        assert!(map.contains_key("agorabus"), "agorabus should be in built-ins");
        assert!(map.contains_key("recalld"), "recalld should be in built-ins");
    }

    /// Verify that a user config at a temp path correctly overrides a built-in.
    #[test]
    fn user_config_overrides_builtin() {
        let tmp = tempfile::tempdir().unwrap();

        // Write a minimal repos.toml.
        let cfg_dir = tmp.path().join(".config/binstale");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        let cfg = cfg_dir.join("repos.toml");
        std::fs::write(&cfg, "[repos]\nagorabus = \"/tmp/custom-agorabus\"\n").unwrap();

        // Temporarily override HOME (with a simple RAII guard).
        let _guard = EnvGuard::set("HOME", tmp.path().to_str().unwrap_or(""));
        let map = load_repo_map();
        assert_eq!(
            map.get("agorabus").map(|p| p.to_string_lossy().into_owned()),
            Some("/tmp/custom-agorabus".to_owned()),
            "user config should override built-in"
        );
    }

    /// Verify no_source skips even an existing (but non-git) directory.
    #[test]
    fn no_source_skips_even_existing_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_path = tmp.path().join("some-repo");
        std::fs::create_dir_all(&repo_path).unwrap();
        let mut map = HashMap::new();
        map.insert("myapp".to_owned(), repo_path);

        let info = query_source_info("myapp", Some(1_000_000), &map, true);
        assert!(info.repo_path.is_none(), "no_source must return repo_path=None");
        assert!(!info.behind_head);
    }

    // ── RAII guard to restore an env var after a test ──────────────────────

    struct EnvGuard {
        key: String,
        old: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &str, val: &str) -> Self {
            let old = std::env::var(key).ok();
            // SAFETY: single-threaded test; no concurrent env readers in this test binary.
            #[allow(unsafe_code)]
            unsafe {
                std::env::set_var(key, val);
            }
            Self {
                key: key.to_owned(),
                old,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: single-threaded test; no concurrent env readers in this test binary.
            #[allow(unsafe_code)]
            unsafe {
                match &self.old {
                    Some(v) => std::env::set_var(&self.key, v),
                    None => std::env::remove_var(&self.key),
                }
            }
        }
    }
}
