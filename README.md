# binstale

Running-binary staleness detector: classifies each running process's executing binary as `fresh | deleted-exe | inode-drift | prov-stale | behind-head` using kernel-truth, provfs signals, and source-repository comparison.

Detection only — it never restarts anything.

## The problem

A long-lived daemon can keep executing a binary that no longer matches the source it was built from. The file gets reinstalled underneath it, or a fix lands in git after the process started. Nothing detects that automatically.

**File-level staleness** (Fleet 1): `/proc/2138939/exe` → `/home/jsy/.local/bin/agorabus (deleted)`. The agorabus bus daemon was executing a binary inode the 20:52 reinstall unlinked. Rediscovered by hand across three consecutive self-review runs before binstale existed.

**Source-level staleness** (Fleet 2 — this release): commit `cf98f2d` (v0.4.0 multi-prefix-subscribe) landed 2026-05-28 19:56 PDT and rewrote `src/daemon.rs`. The running daemon's binary was built at 14:55 — predating the fix by ~56 minutes. Its `/proc` exe was a valid on-disk file, not `deleted-exe`, not `inode-drift`. Only source-comparison catches this window.

## Verdict taxonomy

| Verdict | Signal | Confidence |
|---|---|---|
| `deleted-exe` | `/proc/PID/exe` readlink ends in ` (deleted)` — kernel appended it when the backing inode was unlinked | Highest — kernel truth |
| `inode-drift` | Exe path resolves but current on-disk inode differs from the process's running inode — file was replaced in place (atomic rename) | High — stat comparison |
| `prov-stale` | Inode matches, but `user.prov.ts` xattr (provfs stamp) or on-disk mtime is newer than process start time | Medium — provfs / mtime fallback |
| `behind-head` | Binary's effective build timestamp predates the newest `git log -1 -- src/` commit timestamp in the mapped source repo | Source — git comparison |
| `fresh` | None of the above | — |

Priority order: `deleted-exe` > `inode-drift` > `prov-stale` > `behind-head` > `fresh`. When a file-level verdict wins, `behind-head` is still recorded in `evidence.behind_head` if it also fired.

## Usage

```
binstale check <pid>               # verdict for one PID
binstale scan [--match <regex>]    # scan /proc/*/comm against regex
  --format json|table              # default: table
  --no-source                      # skip git comparison (Fleet-1 behavior)
```

Exit codes: `0` = all fresh, `1` = at least one stale, `2` = usage/IO error.

Default `--match` regex: `^(agorabus|recalld|wm-(audio|dialog|stt|tts))$`

JSON output keys: `pid`, `comm`, `exe_path`, `exe_inode`, `ondisk_inode`, `prov_ts`, `proc_start`, `verdict`, `evidence`, `source_repo`, `source_head_ts`, `source_head_commit`

Use `--no-source` to suppress git invocation and the `source_*` fields entirely (reproduces Fleet-1 behavior for environments without the source repos).

## Source-repository map

By default binstale maps the wintermute fleet:

| Daemon comm | Repo |
|---|---|
| `agorabus` | `~/wintermute/agorabus` |
| `recalld` | `~/wintermute/recall` |
| `wm-audio` | `~/wintermute/wintermute-audio` |
| `wm-dialog` | `~/wintermute/wintermute-dialog` |
| `wm-stt` | `~/wintermute/wintermute-stt` |
| `wm-tts` | `~/wintermute/wintermute-tts` |
| `binstale` | `~/wintermute/binstale` |

Override or extend by creating `~/.config/binstale/repos.toml`:

```toml
[repos]
# Override a built-in mapping
agorabus = "/custom/path/to/agorabus"
# Add a new daemon
my-daemon = "/home/user/projects/my-daemon"
```

User entries are merged over built-ins; the same daemon name takes the user value.

When `git` is unavailable or the mapped repo path does not exist, binstale logs a warning to stderr and leaves `source_*` fields `null` — it does not crash, and the exit code is not affected by the git failure alone.

## Install

```sh
cargo install --git https://github.com/j0yen/binstale
```

Or clone and build:

```sh
git clone https://github.com/j0yen/binstale
cd binstale
cargo build --release
cp target/release/binstale ~/.local/bin/
```

## License

MIT OR Apache-2.0
