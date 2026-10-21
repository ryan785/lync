# Lync

Linux vulnerability scanner. A single Go binary that runs as one `systemd`
service, correlates installed packages against multiple curated CVE feeds,
audits host configuration for non-CVE issues, watches critical files for
out-of-band changes, and produces a JSON report rendered as PDF and as
plain text.

```
+----------+   +---------+   +-------------+   +-----------+   +----------+
| collect  | → | match   | → | applicable? | → | + rules   | → | report   |
| facts    |   | vs feed |   | (per-distro |   | (config + |   | JSON,    |
|          |   | data    |   |  judges)    |   |  monitor) |   | then PDF |
+----------+   +---------+   +-------------+   +-----------+   +----------+
```

## What it does

- **CVE matching** against installed packages on Debian / Ubuntu / Rocky /
  RHEL / AlmaLinux / Fedora / Alpine. RPM-aware version comparison.
- **Lookups, not downloads (default)**: each scan asks OSV.dev about the
  installed packages (one batch query, then details for the hits only;
  OSV carries the Debian, Ubuntu, Alpine, Rocky, Alma and RHEL advisory
  data), Red Hat per CVE on RHEL-family hosts, and NVD by CVE id for
  severity. A Debian test host needed about 1 MB of downloads, a 0.3 MB
  cache, 16 MB RSS and 36 s (1.4 s warm) instead of ~120 MB of feeds and
  ~700 MB RSS. `feed.mode: full` keeps the bulk feeds (NVD, Red Hat, Debian
  tracker, Ubuntu USN, Alpine secdb, OSV exports). Lookup mode sends
  package names and versions to api.osv.dev and CVE ids to NVD and Red Hat;
  see [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md#feed).
- **Never a silent "0 findings"**: every report lists the sources queried,
  request counts and whether the CVE section is complete; a failed lookup
  shows a red banner in the PDF and a degraded exit code.
- **Package-manager cross-check**: findings are confirmed against `dnf
  updateinfo` / `apt-get -s` (cached metadata, read-only), and pending
  security updates no lookup explained are reported too.
- **Notifications (service mode)**: re-checks every 6 h and after package
  installs/upgrades, then emails (SMTP, STARTTLS/TLS, optional PDF) or
  posts webhooks (generic JSON with HMAC signature, Slack, Discord, Teams)
  about new findings, newly available fixes and resolved findings, each
  once. `lync notify test` checks the channels.
- **One-liner = PDF + text**: `curl ... run.sh | sudo sh` leaves the PDF
  report and a plain-text copy (`.txt`, with a "fix first" action plan and
  one update command) in your current directory (owned by you) plus a
  log; see [`docs/RUNNER.md`](docs/RUNNER.md).
- **Application inventory**: lockfiles, site-packages, jars, Go/Rust
  binaries and WordPress outside the package manager, looked up on
  OSV.dev with the same client ([`docs/INVENTORY.md`](docs/INVENTORY.md)).
- **RHEL appstream modules**: module-built packages (php, nodejs, ...) are
  compared only against fixes from their own module stream, and NVD CPE
  products match installed subpackages via the source RPM (`php` ->
  `php-fpm`).
- **"Am I affected by CVE-X?"**: `lync cve CVE-ID` gives a verdict
  (affected / possibly affected / not affected / unknown-to-feeds) with
  scriptable exit codes; `lyncd -once` runs agentless over SSH.
- **Applicability filtering** — when an upstream distro has explicitly
  said "not affected" or "won't fix" for a CVE on your specific
  distro+package, the finding is suppressed. Per-provider judges
  (RedHatJudge, DebianJudge, UbuntuJudge) consult curated data so NVD's
  overconfident upstream-CPE matches don't pollute the report.
- **Configuration auditing** — about 60 toggleable checks: sysctl
  hardening, sshd (first-match + Include aware), sudo/ssh-key/docker
  access, world-readable secrets, writable cron scripts, web roots (.env,
  .git, dumps, phpinfo, web shells, PHP-executable upload dirs), nginx
  routing and TLS expiry, effective php.ini per FPM pool, Docker ports
  bypassing firewalld, exposed databases/Redis, stale firewalld openings,
  reboot/boot-kernel/SELinux drift, failed units, update hygiene, EOL
  Node/Python/PHP/images, WireGuard peers. `lync checks` lists them;
  [`docs/CHECKS.md`](docs/CHECKS.md) is the reference.
- **File-integrity monitor** — kernel-pushed inotify events on critical
  config paths (`/etc/ssh/sshd_config`, `/etc/sudoers`, `/etc/shadow`,
  etc.). Real content changes are detected and reported on the next scan.
- **JSON > PDF** — JSON is the canonical artifact. The PDF renderer
  reads back from JSON; `lync render <json>` regenerates a PDF from any
  past report.

## Quick start: install as a service

```sh
curl -fsSL https://raw.githubusercontent.com/ryan785/lync/main/install.sh | sudo sh
```

That downloads the `.deb`, `.rpm` or `.apk` for your machine (amd64 or
arm64) from the latest GitHub Release, verifies it against `SHA256SUMS`,
installs it with `apt-get`, `dnf`/`yum`/`zypper` or `apk`, and the package
starts the `lync` systemd service. Nothing is compiled and no build tools
are installed. Pin a release with `... | sudo sh -s -- --version v0.2.0`.

```sh
systemctl status lync
lync status
lync scan        # first scan now; reports land in /var/lib/lync/reports/
```

Prefer to install the package yourself? Every release has
`lync-linux-<arch>.{deb,rpm,apk}`:

```sh
sudo apt-get install ./lync-linux-amd64.deb                # Debian / Ubuntu
sudo dnf install ./lync-linux-amd64.rpm                    # Rocky / RHEL / Alma / Fedora
sudo apk add --allow-untrusted ./lync-linux-amd64.apk      # Alpine (no systemd: run lyncd yourself)
```

Upgrades restart the service and keep your `/etc/lync/lync.yaml`; removal
stops and disables it. On hosts without systemd the package installs
cleanly and tells you how to run `lyncd`. Details, uninstall and distro
notes: [`docs/INSTALL.md`](docs/INSTALL.md).

## Scan once, install nothing

Run a full scan (all feeds, judges, every check, PDF + text report) and leave **only a
log file** behind. Details, cleanup guarantees and exit codes are in
[`docs/RUNNER.md`](docs/RUNNER.md).

On the host itself:

```sh
curl -fsSL https://github.com/ryan785/lync/releases/latest/download/run.sh | sudo sh
```

From your workstation over SSH (Git Bash on Windows is fine):

```sh
make release                         # or download dist/ assets from a release
./lync-run root@host.example.com     # report lands in ./lync-results/<UTC>/<host>/
./lync-run --cve CVE-2026-109618 -f hosts.txt --cache ~/.cache/lync-feeds
```

Either way: private temp dir (mode 700, noexec-aware, space-checked),
SHA256-verified static binary, low priority, timeouts, and a trap that
removes everything on exit, Ctrl-C or SSH hangup. The log at
`/var/log/lync-run-<UTC>.log` records every command, download, file and
check.

## Build from source (developers)

Needs Go 1.23+ (and `nfpm` for packages):

```sh
git clone https://github.com/ryan785/lync.git && cd lync
make build && make test
sudo make install && sudo systemctl daemon-reload && sudo systemctl enable --now lync
make release     # dist/: static binaries, .deb/.rpm/.apk, tarballs, run.sh, SHA256SUMS
```

## First-run workflow

```sh
# Confirm the daemon is up
lync status

# Trigger an immediate scan (otherwise it runs on the daily timer)
lync scan
lync status              # watch the active jobs table
ls /var/lib/lync/reports # JSON + PDF + TXT appear here when the scan finishes

# Scoped scans target one package or service
lync scan -package openssh
lync scan -service sshd
lync scan -kernel

# One CVE, right now (sync first if it was just published)
lync cve CVE-2026-109618

# Which checks run, and how to switch them off (rules.disable in lync.yaml)
lync checks

# Older reports
lync reports
lync render /var/lib/lync/reports/lync-2026-05-13_18-30-18.json    # regenerate PDF
lync render /var/lib/lync/reports/lync-2026-05-13_18-30-18.json out.txt  # or the text report
```

The first feed sync takes ~25 minutes without an NVD API key (NVD rate
limits unauthenticated clients to 5 req / 30 sec). With a key it's
seconds — see [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md#nvd-api-key).

## Documentation

| Topic | File |
|---|---|
| Installation, upgrade, uninstall | [`docs/INSTALL.md`](docs/INSTALL.md) |
| Configuration reference (`lync.yaml`) | [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) |
| Every check, its ID and severity | [`docs/CHECKS.md`](docs/CHECKS.md) |
| CLI reference | [`docs/CLI.md`](docs/CLI.md) |
| Architecture & data flow | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| Adding feeds, judges, and rules | [`docs/EXTENDING.md`](docs/EXTENDING.md) |
| Report format (JSON, PDF, text) | [`docs/REPORTS.md`](docs/REPORTS.md) |
| Troubleshooting | [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) |

## Status

| Phase | Subject | State |
|---|---|---|
| 1 | RPM collector, NVD + Red Hat feeds, CVE matcher, PDF/JSON, `.rpm` | done |
| 2 | dpkg/apk collectors, Debian / Ubuntu / Alpine / OSV feeds, judges, `.deb` | done |
| 3 | Rules engine: hardening, sshd, sudo, accounts, filesystem, network, EOL | done |
| 4 | File-integrity monitor (inotify) | done |
| 5 | eBPF behavioral observation | stub — see [`internal/monitor/ebpf.go`](internal/monitor/ebpf.go) |

Not yet done: container image scanning, fleet view, live config reload,
OpenRC init script, SUSE feed/judge. See [`docs/ROADMAP.md`](docs/ROADMAP.md).

## License

MIT — see [`LICENSE`](LICENSE).
