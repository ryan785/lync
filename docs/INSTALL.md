# Installation

Lync ships as a native package (`.deb`, `.rpm`, `.apk`) for Linux amd64 and
arm64. The package contains two static binaries and a systemd unit; it has
no dependencies and nothing is compiled on the target. Installing it starts
the `lync` service.

1. [Install the package](#install-the-package) (recommended)
2. [Scan once without installing](#scan-once-without-installing)
3. [Build from source](#build-from-source) (developers)

## Install the package

### One-liner

```sh
curl -fsSL https://raw.githubusercontent.com/ryan785/lync/main/install.sh | sudo sh
```

A specific release:

```sh
curl -fsSL https://raw.githubusercontent.com/ryan785/lync/main/install.sh | sudo sh -s -- --version v0.2.0
```

[`install.sh`](../install.sh) is a short POSIX `sh` script; read it before
piping it to `sh` if you prefer. It:

1. detects the architecture (`amd64` or `arm64`) and the package manager
   (`apt-get` → `.deb`; `dnf`, `yum` or `zypper` → `.rpm`; `apk` → `.apk`);
2. downloads `lync-linux-<arch>.<ext>` and `SHA256SUMS` from the GitHub
   Release into a temporary directory and verifies the checksum;
3. installs the local file with the native tool (`apt-get install`,
   `dnf install`, `yum install`, `zypper install`, `apk add`);
4. removes the temporary directory and prints `systemctl status lync`,
   `lync version` and the uninstall command.

It installs no compilers, build tools or other packages, and clones
nothing. On a distro without any of those package managers it installs the
static binaries, config and systemd unit by hand under the same paths
(from `lync-linux-<arch>.tar.gz`).

Options: `--version vX.Y.Z` (default: latest release) and `--base-url URL`
(a directory holding the release assets, for mirrors or air-gapped hosts;
`file:///path/to/dist` works). Environment equivalents: `LYNC_VERSION`,
`LYNC_BASE_URL`, `LYNC_REPO`.

### What the package does

| Path | Purpose |
|---|---|
| `/usr/sbin/lyncd` | daemon (static binary) |
| `/usr/bin/lync` | CLI |
| `/etc/lync/lync.yaml` | configuration (kept on upgrade if you edited it) |
| `/usr/lib/systemd/system/lync.service` | systemd unit |
| `/var/lib/lync/feeds/` | cached vulnerability data |
| `/var/lib/lync/reports/` | JSON + PDF reports |

Logs go to the journal (`journalctl -u lync`).

- **Install**: when the host runs systemd, the package enables and starts
  `lync.service`. The daemon is up within a second; the first feed sync
  then runs in the background (see the NVD note under
  [Network access](#network-access)).
- **Upgrade**: the service is restarted if it was enabled or running.
  `/etc/lync/lync.yaml` is not overwritten when you changed it (`.deb` and
  `.rpm` treat it as a config file; `.apk` saves the new default next to it).
- **Remove**: the service is stopped and disabled. Feed caches and reports
  under `/var/lib/lync` are kept; `apt-get purge lync` also deletes
  `/etc/lync` and `/var/lib/lync`.
- **No systemd** (containers, WSL without systemd, Alpine with OpenRC): the
  install succeeds and prints how to run the daemon instead. Start it with
  `/usr/sbin/lyncd &`, or run a single scan with `lyncd -once` (prints the
  JSON report; see `lyncd -h`).

Check it:

```sh
systemctl status lync
lync status
lync scan            # first scan now instead of waiting for the daily schedule
ls /var/lib/lync/reports/
```

### Install a package by hand

Every release has the packages under stable names
(`lync-linux-amd64.deb`, `lync-linux-arm64.rpm`, ...) and versioned names
(`lync_0.2.0-1_amd64.deb`, `lync-0.2.0-1.x86_64.rpm`,
`lync_0.2.0-r1_x86_64.apk`). Download one plus `SHA256SUMS` from the
[releases page](https://github.com/ryan785/lync/releases), then:

```sh
sha256sum -c --ignore-missing SHA256SUMS

# Debian / Ubuntu
sudo apt-get install ./lync-linux-amd64.deb

# Rocky / RHEL / AlmaLinux / CentOS / Fedora / Oracle Linux
sudo dnf install ./lync-linux-amd64.rpm          # or: yum install

# openSUSE / SLES
sudo zypper install --allow-unsigned-rpm ./lync-linux-amd64.rpm

# Alpine
sudo apk add --allow-untrusted ./lync-linux-amd64.apk
```

The packages are not GPG-signed; `SHA256SUMS` is the integrity check.

### Upgrade

Run the one-liner again (or install the newer package file the same way).
To go back to an older release on Debian/Ubuntu, pass `--version`; on
RPM systems use `dnf downgrade ./lync-<version>-1.<arch>.rpm`.

### Uninstall

```sh
sudo apt-get remove lync        # Debian / Ubuntu (purge: also config + data)
sudo dnf remove lync            # RPM family (yum / zypper remove likewise)
sudo apk del lync               # Alpine
```

Installed by hand (no package manager):

```sh
sudo systemctl disable --now lync
sudo rm -f /usr/sbin/lyncd /usr/bin/lync /usr/lib/systemd/system/lync.service
sudo systemctl daemon-reload
sudo rm -rf /etc/lync /var/lib/lync      # config, feed caches and reports
```

## Scan once without installing

`run.sh` downloads the static `lyncd` into a private temp directory,
verifies it, runs one full scan and removes everything except a log file:

```sh
curl -fsSL https://github.com/ryan785/lync/releases/latest/download/run.sh | sudo sh
```

From a workstation over SSH, `lync-run` does the same for many hosts. See
[`RUNNER.md`](RUNNER.md).

## Distro notes

### Debian / Ubuntu

- Tested Ubuntu codenames: `bionic` (18.04), `focal` (20.04), `jammy`
  (22.04), `mantic` (23.10), `noble` (24.04), `oracular` (24.10), `plucky`
  (25.04). Tested Debian: `bullseye` (11), `bookworm` (12), `trixie` (13).
- The UbuntuJudge fetches per-CVE details from `ubuntu.com` and caches them
  under `/var/lib/lync/feeds/ubuntu/details/`. The DebianJudge uses the
  bulk Debian Security Tracker JSON pulled on every sync.

### RHEL family

- Tested on RHEL 9, Rocky Linux 9, AlmaLinux 9 and Oracle Linux 9. The
  RHEL 8 family should work but lacks dedicated test coverage.
- The RedHatJudge fetches per-CVE details from
  `access.redhat.com/hydra/rest/securitydata/cve/<id>.json`, cached under
  `/var/lib/lync/feeds/redhat/details/`.

### Alpine

Alpine uses OpenRC, so the `.apk` installs the binaries and config but no
running service (an OpenRC script is on the roadmap). Until then, add one
yourself:

```sh
# /etc/init.d/lync
#!/sbin/openrc-run
command="/usr/sbin/lyncd"
command_background=yes
pidfile="/run/lync.pid"
output_log="/var/log/lync.log"
error_log="/var/log/lync.log"
depend() { need net; }
```

```sh
sudo chmod +x /etc/init.d/lync
sudo rc-update add lync default
sudo rc-service lync start
```

## Requirements

- Linux kernel 3.10 or newer, amd64 or arm64.
- systemd to run the daemon as a service (RHEL 7+, Debian 8+, Ubuntu
  16.04+, ...). Without it, run `lyncd` directly or use `lyncd -once`.
- Root. The daemon reads `/etc/shadow`, every process's `/proc/*/maps` and
  owner-restricted paths. The unit hardens with `ProtectSystem=full`,
  `ProtectHome=read-only` and `NoNewPrivileges=true`.

### Network access

Outbound HTTPS to:

- `services.nvd.nist.gov` (NVD)
- `access.redhat.com` (Red Hat Security Data)
- `security-tracker.debian.org` (Debian)
- `ubuntu.com` (Ubuntu)
- `secdb.alpinelinux.org` (Alpine)
- `osv-vulnerabilities.storage.googleapis.com` (OSV)
- `endoflife.date` (EOL data, rules engine)

Disable feeds you don't need in `lync.yaml`. Without an NVD API key the
first NVD sync is slow (NVD rate-limits unauthenticated clients); see
[`CONFIGURATION.md`](CONFIGURATION.md#nvd-api-key).

## Build from source

For developers. End users should install the package.

| Component | Minimum | Notes |
|---|---|---|
| Go | 1.23 | `go.mod` pins this; newer is fine |
| Make | any | optional; the `go build` lines in the `Makefile` work without it |
| nfpm | 2.x | only to build the `.deb` / `.rpm` / `.apk` |

```sh
git clone https://github.com/ryan785/lync.git
cd lync
make build                 # bin/lyncd, bin/lync for this host
make test
sudo make install          # same paths as the package
sudo systemctl daemon-reload
sudo systemctl enable --now lync
```

The binaries are static (`CGO_ENABLED=0`), about 8 MB, and run on any
Linux distribution from kernel 3.10 onward.

### Release artifacts and packages

```sh
make release               # everything below into dist/, plus SHA256SUMS
make binaries              # dist/lyncd-linux-{amd64,arm64}, dist/lync-linux-{amd64,arm64}
make packages              # .deb/.rpm/.apk for both arches (needs nfpm)
make tarballs              # dist/lync-linux-<arch>.tar.gz
```

The version comes from `git describe` (override with `make release
VERSION=v0.2.0`); packages drop the leading `v`. Pushing a `v*` tag runs
the same build in GitHub Actions, installs the `.deb` through `install.sh`
on a systemd runner as a smoke test, and publishes the GitHub Release.
