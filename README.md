# binstale

Running-binary staleness detector: classifies each running process's executing binary as `fresh | deleted-exe | inode-drift | prov-stale` using kernel-truth and provfs signals.

Detection only — it never restarts anything.

## The problem

A long-lived daemon can keep executing a binary that no longer matches the source it was built from. The file gets reinstalled underneath it, or a fix lands in git after the process started. Nothing detects that automatically.

Observed live: `/proc/2138939/exe` → `/home/jsy/.local/bin/agorabus (deleted)`. The agorabus bus daemon (started 13:27:36) was executing a binary inode that the 20:52 reinstall unlinked. That finding was rediscovered by hand across three consecutive self-review runs before binstale existed.

## Verdict taxonomy

| Verdict | Signal | Confidence |
|---|---|---|
| `deleted-exe` | `/proc/PID/exe` readlink ends in ` (deleted)` — kernel appended it when the backing inode was unlinked | Highest — kernel truth |
| `inode-drift` | Exe path resolves but current on-disk inode differs from the process's running inode — file was replaced in place (atomic rename) | High — stat comparison |
| `prov-stale` | Inode matches, but `user.prov.ts` xattr (provfs stamp) or on-disk mtime is newer than process start time | Medium — provfs / mtime fallback |
| `fresh` | None of the above | — |

## Usage

```
binstale check <pid>               # verdict for one PID
binstale scan [--match <regex>]    # scan /proc/*/comm against regex
  --format json|table              # default: table
```

Exit codes: `0` = all fresh, `1` = at least one stale, `2` = usage/IO error.

Default `--match` regex: `^(agorabus|recalld|wm-(audio|dialog|stt|tts))$`

JSON output keys: `pid`, `comm`, `exe_path`, `exe_inode`, `ondisk_inode`, `prov_ts`, `proc_start`, `verdict`, `evidence`

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
