# Installation

Lync runs anywhere a single static Go binary can run. The recommended path on
each major distribution is below; the build-from-source path applies
everywhere Go is available.

## Prerequisites

- Linux kernel 3.10+ (any supported distro release)
- `systemd` for the daemon unit (RHEL 7+, Debian 8+, Ubuntu 16.04+, etc.).
  Alpine and OpenRC-based systems can run `lyncd` directly; see
  [Alpine notes](#alpine).
- Root for the daemon. Lync needs root to read `/etc/shadow`, query every
  process's `/proc/*/maps`, and use inotify on owner-restricted paths. The
  systemd unit hardens with `ProtectSystem=full`, `ProtectHome=true`, and
  `NoNewPrivileges=true`.
- Outbound HTTPS to:
  - `services.nvd.nist.gov` (NVD)
  - `access.redhat.com` (Red Hat Security Data)
  - `security-tracker.debian.org` (Debian)
  - `ubuntu.com` (Ubuntu)
  - `secdb.alpinelinux.org` (Alpine)
  - `osv-vulnerabilities.storage.googleapis.com` (OSV)
  - `endoflife.date` (EOL data, rules engine)
  - Disable feeds you don't need in `lync.yaml`.

## Debian / Ubuntu

### From source

```sh
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

`make install` writes:

| Path | Purpose |
|---|---|
| `/usr/sbin/lyncd` | daemon binary |
| `/usr/bin/lync` | CLI |
| `/etc/lync/lync.yaml` | default configuration |
| `/etc/lync/rules.d/` | user-extensible YAML checks (Phase 3.x) |
| `/usr/lib/systemd/system/lync.service` | systemd unit |
| `/var/lib/lync/feeds/` | cached vulnerability data |
| `/var/lib/lync/reports/` | generated reports |
| `/var/log/lync/` | log directory (journald is primary) |

### From a `.deb`

When a release is published:

```sh
sudo dpkg -i lync_0.1.0_amd64.deb
sudo systemctl enable --now lync
```

Build one locally with:

```sh
sudo apt-get install -y golang-go git make
git clone https://github.com/ryan785/lync.git
cd lync
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
PATH="$PATH:$HOME/go/bin" make deb
sudo dpkg -i dist/lync_*.deb
```

### Ubuntu specifics

- Tested release codenames: `bionic` (18.04), `focal` (20.04), `jammy` (22.04),
  `mantic` (23.10), `noble` (24.04), `oracular` (24.10), `plucky` (25.04).
- The UbuntuJudge needs outbound HTTPS to `ubuntu.com` for per-CVE detail
  lookups. Each CVE is cached on disk after first fetch under
  `/var/lib/lync/feeds/ubuntu/details/`.

### Debian specifics

- Tested codenames: `bullseye` (11), `bookworm` (12), `trixie` (13).
- The DebianJudge reads from the bulk Debian Security Tracker JSON pulled by
  `DebianSource` on every sync (no extra HTTP calls per finding).

## Rocky / RHEL / AlmaLinux / CentOS / Fedora

### From source

```sh
sudo dnf install -y golang git make
git clone https://github.com/ryan785/lync.git
cd lync
make build
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now lync
lync status
```

### From an `.rpm`

When a release is published:

```sh
sudo dnf install ./lync-0.1.0-1.x86_64.rpm
sudo systemctl enable --now lync
```

Build one locally with:

```sh
sudo dnf install -y golang git make
git clone https://github.com/ryan785/lync.git
cd lync
GOBIN=/usr/local/bin go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
make rpm
sudo dnf install ./dist/lync-*.x86_64.rpm
```

### RHEL-family specifics

- Tested on RHEL 9, Rocky Linux 9.7, AlmaLinux 9, Oracle Linux 9. RHEL 8
  family should work but lacks dedicated test coverage.
- The RedHatJudge pulls per-CVE detail from
  `access.redhat.com/hydra/rest/securitydata/cve/<id>.json`, cached under
  `/var/lib/lync/feeds/redhat/details/`.

## Alpine

```sh
sudo apk add go git make
git clone https://github.com/ryan785/lync.git
cd lync
make build
sudo make install
```

Alpine uses OpenRC, not systemd. The shipped `lync.service` unit won't be
honored. Run the daemon directly or write an OpenRC init script:

```sh
# /etc/init.d/lync
#!/sbin/openrc-run
command="/usr/sbin/lyncd"
command_background=yes
pidfile="/run/lync.pid"
depend() { need net; }
```

```sh
sudo chmod +x /etc/init.d/lync
sudo rc-update add lync default
sudo rc-service lync start
```

## Build prerequisites

| Component | Minimum | Notes |
|---|---|---|
| Go | 1.23 | `go.mod` pins this. Newer is fine. |
| Git | any | clone the repo |
| Make | any | optional — see the `go build` commands in `Makefile` if you don't have Make |
| nfpm | latest | only needed to build `.rpm` / `.deb`. `go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest` |

The build is statically linked (CGO_ENABLED defaults to 0 because we don't
import any cgo packages). The resulting `lyncd` is around 8 MB and runs on
any glibc-compatible Linux from kernel 3.10 onward.

## Uninstall

```sh
sudo systemctl disable --now lync
sudo rm -f /usr/sbin/lyncd /usr/bin/lync
sudo rm -f /usr/lib/systemd/system/lync.service
sudo systemctl daemon-reload
# To also remove state and cached feed data:
sudo rm -rf /etc/lync /var/lib/lync /var/log/lync
```
