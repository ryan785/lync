# Lync

Linux vulnerability scanner. A single Go binary that runs as one `systemd`
service, correlates installed packages against multiple curated CVE feeds,
audits host configuration for non-CVE issues, watches critical files for
out-of-band changes, and produces a PDF + JSON report.

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
- **Multiple feed sources**: NIST NVD, Red Hat Security Data, Debian
  Security Tracker, Ubuntu USN, Alpine secdb, OSV.dev (enabled by default;
  the full-history source for Rocky/Alma).
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

## Quick start: scan once, install nothing

Run a full scan (all feeds, judges, every check, PDF) and leave **only a
log file** behind. Details, cleanup guarantees and exit codes are in
[`docs/RUNNER.md`](docs/RUNNER.md).

From your workstation over SSH (works while the repo is private; Git Bash
on Windows is fine):

```sh
make release                         # builds dist/lyncd-linux-{amd64,arm64} + SHA256SUMS
./lync-run root@host.example.com     # report lands in ./lync-results/<UTC>/<host>/
./lync-run --cve CVE-2026-109618 -f hosts.txt --cache ~/.cache/lync-feeds
```

On the host itself (needs a published GitHub Release):

```sh
# public repo
curl -fsSL https://github.com/ryan785/lync/releases/latest/download/run.sh | sudo sh
# private repo: fine-grained token with Contents: read
read -rs LYNC_GH_TOKEN; export LYNC_GH_TOKEN
curl -fsSL -H "Authorization: Bearer $LYNC_GH_TOKEN" -H "Accept: application/vnd.github.raw" \
  https://api.github.com/repos/ryan785/lync/contents/run.sh | sudo LYNC_GH_TOKEN="$LYNC_GH_TOKEN" sh
```

Either way: private temp dir (mode 700, noexec-aware, space-checked),
SHA256-verified static binary, low priority, timeouts, and a trap that
removes everything on exit, Ctrl-C or SSH hangup. The log at
`/var/log/lync-run-<UTC>.log` records every command, download, file and
check.

## Quick install (as a service)

### One-liner (any supported distro)

```sh
curl -fsSL https://raw.githubusercontent.com/ryan785/lync/main/install.sh | sudo sh
```

The installer detects your distro (Debian, Ubuntu, Rocky, RHEL, AlmaLinux,
CentOS, Fedora, Alpine, openSUSE, SLES), installs Go + git + make via the
right package manager, clones this repo, builds, installs binaries +
systemd unit, and starts the daemon. See [`install.sh`](install.sh) — it's
a single POSIX-sh file you can read before piping to `sh`.

Override behavior with environment variables:

```sh
# Install but don't start the service yet
curl -fsSL https://raw.githubusercontent.com/ryan785/lync/main/install.sh | sudo LYNC_START=0 sh

# Install a specific tag
curl -fsSL https://raw.githubusercontent.com/ryan785/lync/main/install.sh | sudo LYNC_REF=v0.1.0 sh

# Run from a local clone (script auto-detects this)
git clone https://github.com/ryan785/lync.git && cd lync
sudo ./install.sh
```

If you'd rather see the manual steps for each distro:

### Debian / Ubuntu

```sh
# Build & install from source
sudo apt-get update
sudo apt-get install -y golang-go git make
git clone https://github.com/ryan785/lync.git
cd lync
make build
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now lync
lync status
```

Or, with a pre-built `.deb` (when releases are published):

```sh
sudo dpkg -i lync_0.1.0_amd64.deb
sudo systemctl enable --now lync
```

### Rocky / RHEL / AlmaLinux / Fedora

```sh
# Build & install from source
sudo dnf install -y golang git make
git clone https://github.com/ryan785/lync.git
cd lync
make build
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now lync
lync status
```

Or, with a pre-built `.rpm`:

```sh
sudo dnf install ./lync-0.1.0-1.x86_64.rpm
sudo systemctl enable --now lync
```

### Alpine

```sh
# Build & install from source
sudo apk add go git make
git clone https://github.com/ryan785/lync.git
cd lync
make build
sudo make install
# Alpine uses OpenRC by default; the systemd unit won't apply without
# systemd. Run the daemon directly or write an OpenRC init script.
sudo /usr/sbin/lyncd &
lync status
```

(Alpine support in the daemon is functional; the OpenRC service file is on
the roadmap.)

### Build a package locally

`nfpm` is required (`go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest`):

```sh
make rpm    # → dist/lync-0.1.0-1.x86_64.rpm
make deb    # → dist/lync_0.1.0_amd64.deb
make package  # both
```

## First-run workflow

```sh
# Confirm the daemon is up
lync status

# Trigger an immediate scan (otherwise it runs on the daily timer)
lync scan
lync status              # watch the active jobs table
ls /var/lib/lync/reports # PDF + JSON appear here when the scan finishes

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
```

The first feed sync takes ~25 minutes without an NVD API key (NVD rate
limits unauthenticated clients to 5 req / 30 sec). With a key it's
seconds — see [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md#nvd-api-key).

## Documentation

| Topic | File |
|---|---|
| Detailed installation per distro | [`docs/INSTALL.md`](docs/INSTALL.md) |
| Configuration reference (`lync.yaml`) | [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) |
| Every check, its ID and severity | [`docs/CHECKS.md`](docs/CHECKS.md) |
| CLI reference | [`docs/CLI.md`](docs/CLI.md) |
| Architecture & data flow | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| Adding feeds, judges, and rules | [`docs/EXTENDING.md`](docs/EXTENDING.md) |
| Report format (JSON + PDF) | [`docs/REPORTS.md`](docs/REPORTS.md) |
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
