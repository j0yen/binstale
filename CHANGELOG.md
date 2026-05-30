# Changelog

All notable changes to `binstale` are documented here.

## [0.2.0] — 2026-05-29

### Added

- **`behind-head` verdict** — new staleness class: a running binary whose effective
  build timestamp predates the newest `git log -1 -- src/` commit timestamp in the
  mapped source repository. Catches the run-18 agorabus 19:56→20:52 window: commit
  `cf98f2d` (v0.4.0) rewrote `src/daemon.rs` at 19:56 PDT; the binary built at 14:55
  was silently stale for ~56 minutes with no file-level signal.

- **`src/source.rs`** — new module: daemon→repo mapping, git source-head query, and
  `behind-head` comparison logic.

- **`--no-source` flag** — skips all git invocation and `behind-head` detection;
  reproduces Fleet-1 `/proc`-only behavior exactly. No `git` subprocess is spawned
  when `--no-source` is set (verifiable by running with `git` off PATH).

- **`~/.config/binstale/repos.toml` config** — user-supplied daemon→repo overrides,
  merged over built-in wintermute fleet defaults.

- **Built-in fleet map**: `agorabus`, `recalld`, `wm-audio`, `wm-dialog`, `wm-stt`,
  `wm-tts`, `binstale` → their respective `~/wintermute/<slug>` repos.

- **New JSON fields**: `source_repo`, `source_head_ts`, `source_head_commit`
  (all `null` for unmapped processes or when `--no-source` is set).

- **`evidence.behind_head`** — recorded even when a file-level verdict outranks it,
  so callers can observe the full signal set.

- **`toml` dependency** (`0.8`, parse-only features) for reading `repos.toml`.

- **`tempfile` dev-dependency** for source module tests.

### Changed

- Verdict taxonomy now includes `behind-head` (ranks below file-level verdicts).
- `--help` text updated to document `behind-head`, `--no-source`, and source map.
- README updated with worked example (run-18 agorabus window), verdict table,
  and `repos.toml` format.

### Behavior unchanged

- All Fleet-1 acceptance criteria (verdict taxonomy, exit codes, provfs fallback)
  pass unchanged when `--no-source` is set or no repo mapping exists.
- `git` failure (not on PATH, repo missing, no `src/` commits) degrades gracefully:
  logs a warning to stderr, leaves `source_*` null, exit code unaffected.

## [0.1.0] — 2026-05-28

### Added

- Initial release: `deleted-exe`, `inode-drift`, `prov-stale`, `fresh` verdicts.
- `binstale check <pid>` and `binstale scan [--match <regex>]` subcommands.
- JSON and table output formats.
- Exit codes: `0` = all fresh, `1` = any stale, `2` = error.
- Provfs `user.prov.ts` xattr support with mtime fallback.
