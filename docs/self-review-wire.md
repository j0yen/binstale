# binstale — self-review fleet-health wiring

## Fleet-health phase snippet

Add this to the fleet-health phase of `~/.claude/skills/self-review/self-review.sh`
(or equivalent self-review playbook) to automatically file docket items when any
wintermute daemon is running a stale binary:

```sh
# --- Fleet staleness check (binstale) ---
if command -v binstale >/dev/null 2>&1; then
  docket_lines=$(binstale fleet --format docket --no-source 2>/dev/null)
  if [ -n "$docket_lines" ]; then
    echo "$docket_lines" | sh
  fi
else
  echo "binstale not installed — fleet staleness check skipped"
fi
```

### With source comparison (git)

Drop `--no-source` to also detect `behind-head` verdicts (requires git and
the wintermute source repos on disk):

```sh
if command -v binstale >/dev/null 2>&1; then
  docket_lines=$(binstale fleet --format docket 2>/dev/null)
  if [ -n "$docket_lines" ]; then
    echo "$docket_lines" | sh
  fi
fi
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | All fleet processes are fresh |
| 1    | At least one process is stale (docket items were filed) |
| 2    | Error reading /proc or other I/O failure |

### Docket severity mapping

| Verdict     | Severity |
|-------------|----------|
| deleted-exe | alert    |
| inode-drift | alert    |
| prov-stale  | warn     |
| behind-head | warn     |

### Install / update binstale

```sh
bash ~/wintermute/binstale/scripts/install.sh
```

The script builds a release binary in the cloud (via `cloudbuild.sh`) and
installs it to `~/.local/bin/binstale`. Run after any source change to
`~/wintermute/binstale/`.
