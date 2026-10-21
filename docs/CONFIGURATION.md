# Configuration

Lync reads `/etc/lync/lync.yaml` at startup. The shipped default lives at
[`packaging/config/lync.yaml`](../packaging/config/lync.yaml) — copying that
file gives you a working setup. Everything below documents what each key
does and what changes when you tweak it.

The daemon **does not live-reload its config**. After editing `lync.yaml`
run `systemctl restart lync`. `systemctl reload lync` (SIGHUP) only
validates the file and logs whether it is valid; it does not apply it.
Invalid intervals (zero/negative `scan.interval` or `feed.sync_interval`),
empty `cache_dir`/`report.dir`, or negative `retention_days` are rejected
at startup with a clear error.

---

## Top-level structure

```yaml
log:
scan:
feed:
report:
ipc:
applicability:
monitor:
```

## `log`

```yaml
log:
  level: info         # error | warn | info | debug
  format: logfmt      # logfmt | json
```

- **`level`** — `debug` enables per-package matcher diagnostics and per-CVE
  applicability decisions. Useful when investigating a missing finding or
  an unexpected suppression. `trace` is currently an alias for `debug`.
- **`format`** — `logfmt` is the default journald-friendly text format.
  `json` for log shippers (Fluent Bit, Vector, etc.).

## `scan`

```yaml
scan:
  interval: 24h
  on_start: false
```

- **`interval`** — gap between scheduled full-host scans. Each scan reads
  installed packages and matches them against the **cached** vuln data —
  it does not refetch feeds. A scan takes 1-4 seconds on a typical host.
- **`on_start`** — run an immediate scan when the daemon starts. Default
  `false` because the daemon hasn't necessarily synced feeds yet. Once
  `Last sync` is populated the daemon's scheduled tick will trigger
  normal scans.

Trigger a scan on demand with `lync scan` (or scoped: `lync scan -package <name>`).

## `feed`

```yaml
feed:
  sync_interval: 6h
  cache_dir: /var/lib/lync/feeds
  sources:
    - name: redhat
      enabled: true
    - name: osv
      enabled: true
    - name: nvd
      enabled: true
      api_key: ""
    # - name: debian
    #   enabled: true
    # - name: ubuntu
    #   enabled: true
    # - name: alpine
    #   enabled: true
```

- **`sync_interval`** — how often the daemon refreshes its cached vuln data.
  Each source pulls its own bulk feed; total time depends on the source
  (NVD with no API key: ~25 min for 120-day window, ~2 min for 30-day).
- **`cache_dir`** — on-disk vuln cache. Each source writes its own subdirectory
  (`redhat/`, `nvd/`, `debian/`, etc.). Per-CVE detail caches (RedHatJudge,
  UbuntuJudge) live under `redhat/details/` and `ubuntu/details/`.
- **`sources[]`** — which feeds are active. Adding a source name not in the
  built-in registry is silently ignored. Built-in names:
  - `redhat` — Red Hat Security Data API summary feed. Rolling **365-day**
    window by CVE public date; RPM fixes only (appstream module errata are
    listed as module NSVCs and skipped). Not CSAF/VEX.
  - `osv` — OSV.dev bulk export for the host's own distro ecosystem
    (`Rocky Linux:N`, `AlmaLinux:N`, `Red Hat:N`, `Debian:N`, `Ubuntu:X`,
    `Alpine:vX`). Full advisory history with per-RPM fixed versions,
    including module packages (php, nodejs, postgresql...). **Enabled by
    default; on Rocky this is the main source of history.**
  - `nvd` — NIST NVD, distro-agnostic CPE ranges. 30-day window without an
    API key, 120 days with one. Matched by binary name or, failing that, by
    source package name (CPE `php` matches `php-fpm`). Dropped whenever a
    distro-scoped source says the installed build is already patched.
  - `debian` — Debian Security Tracker
  - `ubuntu` — Ubuntu Security Notices
  - `alpine` — Alpine secdb

### NVD API key

NVD allows 5 requests / 30 sec without a key (slow, suitable for a 30-day
sync window) and 50 requests / 30 sec with one (full 120-day window in
seconds). Request a free key at
[nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
and set:

```yaml
feed:
  sources:
    - name: nvd
      enabled: true
      api_key: "00000000-1111-2222-3333-444455556666"
```

The daemon will detect the presence of a key and switch to the longer
window automatically.

### Initial sync skip

The daemon caches feed manifests per source. On startup it inspects each
source's manifest age — if every source is younger than `sync_interval`
the initial sync is skipped. Daemon restarts during development don't
re-pull 25-minute NVD data.

## `report`

```yaml
report:
  dir: /var/lib/lync/reports
  retention_days: 0
```

- **`dir`** — where `lync-<timestamp>.{json,pdf}` reports are written.
- **`retention_days`** — `0` means keep forever. A positive integer deletes
  `lync-*.json` / `lync-*.pdf` files in `dir` older than N days after each
  scan.

## `ipc`

```yaml
ipc:
  socket: /run/lync.sock
```

Path to the Unix domain socket the daemon listens on. The `lync` CLI
connects here. Mode `0660` so root + group can talk to it.

## `applicability`

```yaml
applicability:
  enabled: true
  concurrency: 5
  suppress_on:
    - not_affected
    - deferred_or_wontfix
```

- **`enabled`** — set `false` to bypass the post-match applicability filter
  entirely. Useful when investigating why a CVE was suppressed.
- **`concurrency`** — number of judges polled in parallel for any one
  finding. 5 is conservative; raise it if the host has good outbound
  bandwidth and a NVD/Ubuntu detail cache that's cold.
- **`suppress_on`** — labels of statuses that drop a finding from the
  report:
  - `not_affected` — distro explicitly reviewed and said it doesn't apply.
    Safe default.
  - `deferred_or_wontfix` — distro has acknowledged the bug but won't ship
    a fix (low real-world impact, EOL stream, etc.). Suppressed by default
    because most operators want practical impact, not theoretical exposure.
  - `affected` — never suppress (this would hide real findings).
  - `unknown` — never suppress (means no judge has data for that CVE).

Per-judge cache locations:
- RedHat: `/var/lib/lync/feeds/redhat/details/<CVE>.json`
- Ubuntu: `/var/lib/lync/feeds/ubuntu/details/<CVE>.json`
- Debian: in-memory index built from the bulk feed cache; no separate
  detail cache.

## `rules`

```yaml
rules:
  enabled: true
  level: medium            # basic | medium | strict (original rules only)
  disable: []              # check IDs, ID prefixes or rule names
  enable: []               # wins over disable; required for opt-in checks
  image_max_age_days: 365  # container:image-age threshold
  wireguard_stale_days: 90 # wireguard:stale-peer threshold
  secret_scan_dirs: []     # extra roots for the compose/.env secret scan
  root: ""                 # read the filesystem under this prefix (tests, mounted images)
```

- **`disable` / `enable`** accept three forms: an exact check ID
  (`php:expose-php`), an ID prefix (`docker` matches `docker:group-members`
  and `docker:socket-perms`, but `web:php` does *not* match `web:phpinfo`),
  or a rule name (`ssh-config`, `runtimes`). They apply to the original
  rules too, by finding-ID prefix (e.g. `nginx:no-hsts`). `enable` wins, so
  `disable: [php]` + `enable: [php:upload-progress]` keeps only that one.
- **Opt-in checks** are off unless enabled. Currently only
  `container:php-upload-progress`, because it runs `docker exec <c> php -r`.
- **`root`** only affects the checks built on `rules.Host` (all checks added
  in 2026-10: web, php, exposure, system, access, runtimes, vpn, and the
  ssh compound check). The original rules still read `/`.

`lync checks` prints every check with its on/off state under a config file;
[`CHECKS.md`](CHECKS.md) is the reference table.

## `monitor`

```yaml
monitor:
  enabled: true
  file_integrity:
    enabled: true
    paths:
      - /etc/ssh/sshd_config
      - /etc/sudoers
      - /etc/sudoers.d
      - /etc/passwd
      - /etc/shadow
      - /etc/pam.d
      - /etc/crontab
      - /etc/cron.d
      - /root/.ssh/authorized_keys
```

- **`monitor.enabled`** — master switch.
- **`file_integrity.enabled`** — toggle inotify watcher independently.
- **`file_integrity.paths`** — both files and directories. Directories are
  walked once at startup to baseline contents; inotify events fire on
  modifications inside.

When a watched file changes:
1. Lync re-fingerprints (mode + size + SHA-256 if regular and < 4 MiB)
2. If content actually differs, accumulates a `runtime` Finding
3. The finding appears in the next scan's report

Spurious events (e.g. `touch` with no content change) are filtered out by
the hash comparison. Files larger than 4 MiB are tracked by mode + size +
mtime only; this avoids hashing log files if someone misconfigures `paths`.

## Severity normalization

Lync's severity vocabulary is `Critical / High / Medium / Low / Info / Unknown`.
Each provider maps to it:

| Provider | Provider label | Lync severity |
|---|---|---|
| Red Hat | Critical | Critical |
| Red Hat | Important | High |
| Red Hat | Moderate | Medium |
| Red Hat | Low | Low |
| Debian | high (urgency) | High |
| Debian | medium | Medium |
| Debian | low | Low |
| NVD | CVSSv3 >= 9.0 | Critical |
| NVD | 7.0–8.9 | High |
| NVD | 4.0–6.9 | Medium |
| NVD | 0.1–3.9 | Low |

Provider severity always wins over the CVSS-derived fallback. So a CVE
that Red Hat labels Low but NVD scores at 9.8 will show as Low in the
report — see [`docs/ARCHITECTURE.md`](ARCHITECTURE.md#severity-and-source-priority)
for why.

## Example: minimal NVD-only setup

```yaml
log: { level: info, format: logfmt }
scan: { interval: 24h, on_start: false }
feed:
  sync_interval: 12h
  cache_dir: /var/lib/lync/feeds
  sources:
    - { name: nvd, enabled: true, api_key: "YOUR-NVD-KEY-HERE" }
report: { dir: /var/lib/lync/reports }
ipc: { socket: /run/lync.sock }
applicability: { enabled: false }  # no per-distro curation to fall back on
monitor: { enabled: false }
```

## Example: paranoid hardening setup

```yaml
log: { level: info, format: json }
scan: { interval: 6h, on_start: true }
feed:
  sync_interval: 6h
  sources:
    - { name: redhat, enabled: true }
    - { name: nvd, enabled: true, api_key: "..." }
    - { name: osv, enabled: true }
applicability:
  enabled: true
  suppress_on: [not_affected]   # don't hide deferred / won't-fix
monitor:
  enabled: true
  file_integrity:
    enabled: true
    paths:
      - /etc/ssh
      - /etc/sudoers
      - /etc/sudoers.d
      - /etc/passwd
      - /etc/shadow
      - /etc/group
      - /etc/gshadow
      - /etc/pam.d
      - /etc/crontab
      - /etc/cron.d
      - /etc/cron.daily
      - /etc/cron.hourly
      - /etc/cron.weekly
      - /etc/systemd/system
      - /root/.ssh
      - /home
```
