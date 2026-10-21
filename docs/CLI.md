# `lync` CLI reference

`lync` is the client that talks to the `lyncd` daemon over its Unix
domain socket. It's safe to install on hosts that don't run the daemon
as long as you mount or symlink the socket from somewhere reachable.

```
lync [global flags] <command> [command flags]
```

## Global flags

| Flag | Default | Description |
|---|---|---|
| `-socket <path>` | `/run/lync.sock` | IPC socket path |
| `-json` | off | Print raw JSON instead of formatted text |
| `-color <when>` | `auto` | `auto` (TTY detect), `always`, `never` |
| `-no-color` | off | Shorthand for `-color=never`. Also `NO_COLOR=1` env var |

## Commands

### `lync status`

Show daemon state, last scan, last sync, and currently-running jobs.

```
$ lync status
lync 0.1.0
------------------------------------------------------------
Daemon:     running  (up 2h 14m)
Sources:    redhat, nvd
Last scan:  2026-05-13 17:30:35  (44m 7s ago, 39 findings)
Last sync:  2026-05-13 17:30:20  (44m 22s ago)
Last PDF:   /var/lib/lync/reports/lync-2026-05-13_17-30-35.pdf

Active jobs:
  KIND  STARTED   ELAPSED  SCOPE
  scan  18:14:42  0s       all
```

When the daemon is idle the table reads `(idle)`. Add `-json` for
machine-readable output.

### `lync scan [flags]`

Trigger an immediate scan. Without flags, scans the whole host. With
flags, filters down to one package or service so subsequent scoped
reports are smaller and faster.

| Flag | Description |
|---|---|
| `-package <name>` | Scan only the named package |
| `-service <name>` | Scan the package providing the named systemd service (`.service` suffix optional) |
| `-kernel` | Scan only the kernel |

Examples:

```sh
lync scan
lync scan -package openssh
lync scan -service sshd       # equivalent: resolves sshd.service -> openssh-server
lync scan -kernel
```

Scoped scans produce reports with a descriptive filename suffix:
`lync-2026-05-13_17-20-40-pkg_openssh.pdf`. Scoped scans **do not**
overwrite the daemon's "last scan" pointer — that always reflects the
canonical full-host state.

Scan is asynchronous: the CLI returns immediately with `Scan queued`.
Use `lync status` to watch progress.

### `lync sync`

Force an immediate feed refresh. Useful when you've just landed a new
NVD API key or want to pull the latest data without waiting for the
scheduled tick.

```sh
lync sync
```

This is a force-refresh — it ignores the cache-age check that
`maybeInitialSync` does at daemon start.

### `lync reports`

List previously generated reports, newest first.

```
$ lync reports
WHEN              SIZE   NAME
2026-05-13 18:37  9.5K   lync-2026-05-13_18-37-40.pdf
2026-05-13 18:30  37.6K  lync-2026-05-13_18-30-18.pdf
2026-05-13 17:30  53.0K  lync-2026-05-13_17-30-35-kernel.pdf
2026-05-13 17:20  3.6K   lync-2026-05-13_17-20-40-pkg_openssh.pdf
```

### `lync render <json> [pdf]`

Regenerate a PDF from any past JSON report. If you omit the PDF path,
it's the JSON path with `.json` replaced by `.pdf`.

```sh
lync render /var/lib/lync/reports/lync-2026-05-13_18-37-40.json
lync render report.json /tmp/output.pdf
```

The JSON is the canonical artifact — modifying it (e.g. piping through
`jq` to add an annotation) and re-rendering produces a customized PDF.

### `lync cve <CVE-ID>`

"Am I affected by CVE-X?" Collects fresh facts, looks the CVE up in every
cached feed, runs the matcher and applicability judges on just that CVE,
and prints a verdict:

| Verdict | Exit | Meaning |
|---|---|---|
| `not_affected` | 0 | Feeds know the CVE; installed builds are at/above the fix, or the named packages aren't installed |
| `affected` | 10 | A fixed version / range says the installed build is vulnerable (findings include remediation) |
| `possibly_affected` | 11 | An installed package is named for this CVE but no fixed version has been published yet |
| `unknown` | 12 | No cached feed has this CVE. **Not** a clean bill of health: run `lync sync` and retry |

It does not sync feeds itself. `-json` prints the full result (known_by,
installed candidates with fixed versions, findings).

```
$ lync sync          # wait for it to finish (lync status)
$ lync cve CVE-2026-109618
```

### `lync checks [-config FILE]`

Lists every rules check (ID, rule, severity, on/off under the config,
description). Reads `lync.yaml` directly, so it works without the daemon.
`-json` gives machine output. IDs are what `rules.disable` /
`rules.enable` take; see [`CHECKS.md`](CHECKS.md).

```
$ lync checks | grep -E 'opt-in|php:'
container:php-upload-progress  runtimes  high  off (opt-in)  PHP inside running containers ...
php:upload-progress            php       high  on            session.upload_progress.enabled is On ...
```

### `lync version`

```
$ lync version
lync 0.1.0
```

### `lync help`

Print the usage text (also printed when called with no arguments).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | usage error (unknown command, bad flag combination) |
| 2 | could not reach the daemon (socket missing, permission denied) |
| 3 | daemon returned an error response |
| 10/11/12 | `lync cve` only: affected / possibly affected / unknown to feeds |

## Color output

`lync` emits ANSI escape codes when stdout is a TTY and `NO_COLOR` is
unset. SSH passes the codes through to your terminal; piped output
(`lync status | less`) is automatically plain. Force one direction:

```sh
lync -color=always status | tee /var/log/lync-status.log   # keep colors
lync -color=never status                                    # strict plain
NO_COLOR=1 lync status                                       # same effect
```

The color scheme follows what's documented in
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md#cli-color-scheme).

## Talking to a remote daemon

The CLI uses a local Unix socket. To reach a daemon on another host:

```sh
# Option A: SSH the command to the host
ssh root@remote 'lync status'

# Option B: forward the socket through SSH
ssh -L /tmp/remote-lync.sock:/run/lync.sock root@remote
lync -socket /tmp/remote-lync.sock status
```

A network-attached HTTP API is intentionally not provided — the IPC
socket is local-only by design so the daemon doesn't need to manage
authentication or transport security.

## One-shot mode (no daemon)

`lyncd -once` runs a single sync-if-stale + scan without opening a socket
or starting the scheduler/monitor, prints the JSON report to stdout and
logs to stderr. `lyncd -once -cve CVE-ID` prints the `lync cve` result
instead. Useful for hosts that don't run the service, and for fleet
collection over SSH:

```sh
scp bin/lyncd root@host:/tmp/lyncd
ssh root@host '/tmp/lyncd -once -cve CVE-2026-109618 -cache-dir /var/tmp/lync-feeds -report-dir /var/tmp/lync-reports'
```

`-cache-dir` keeps the feed cache between runs (OSV + Red Hat + NVD take a
few minutes the first time). See `docs/ROADMAP.md` for the fleet plan.

## Scripting tips

```sh
# Wait for a scan to finish, then process results
lync scan
while lync -json status | jq -e '.data.running | length > 0' > /dev/null; do
  sleep 5
done
latest=$(ls -1t /var/lib/lync/reports/*.json | head -1)
jq '.counts' "$latest"

# Daily compliance: just the High+Critical CVEs as plain text
lync -json status | \
  jq -r '.data.last_json' | \
  xargs -I{} jq -r '.findings[] | select(.severity=="High" or .severity=="Critical") |
    "\(.severity)\t\(.cve)\t\(.package)\t\(.title)"' {}
```
