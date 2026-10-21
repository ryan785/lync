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
rules:
inventory:
monitor:
notify:
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
  interval: 6h
  on_start: false
  on_package_change: true
  package_change_delay: 2m
```

- **`interval`** — gap between scheduled full-host scans (default 6h). In
  lookup mode every scan queries the sources, so this is also how often a
  newly published CVE is noticed. In full mode a scan only matches against
  the cached feeds (refreshed every `feed.sync_interval`).
- **`on_start`** — run a scan as soon as the daemon starts. In lookup mode
  the daemon also scans about 15 s after start whenever the newest report
  is older than `interval`, so restarts and fresh installs don't wait a
  whole interval.
- **`on_package_change`** — watch the package database
  (`/var/lib/rpm`, `/var/lib/dpkg/status`, `/lib/apk/db/installed`) with
  inotify and re-scan once it has been quiet for `package_change_delay`
  (an upgrade run touches the database many times). Reading the database
  never triggers a scan.

Trigger a scan on demand with `lync scan` (or scoped: `lync scan -package <name>`).

## `feed`

```yaml
feed:
  mode: lookup              # lookup (default) | full
  cache_dir: /var/lib/lync/feeds
  local_check: true         # cross-check with dnf/yum/apt, read-only
  local_refresh: false      # refresh package-manager metadata first (opt-in)
  lookup:
    cache_ttl: 24h          # Red Hat per-CVE answers (NVD: 7 days minimum)
    nvd_max_per_run: 0      # 0 = 10 without an API key, 200 with one
    redhat_max_per_run: 500
  sync_interval: 6h         # full mode only
  sources:
    - name: redhat
      enabled: true
    - name: osv
      enabled: true
    - name: nvd
      enabled: true
      api_key: ""
    # - name: nodejs        # upstream Node.js data (nodejs.org index, security-wg, release
    #   enabled: true       # schedule); follows osv when not listed. See ARCHITECTURE.md
    # - name: debian        # full mode: bulk tracker; lookup mode: served by osv
    #   enabled: true
    # - name: ubuntu
    #   enabled: true
    # - name: alpine
    #   enabled: true
```

### `mode: lookup` (default)

Nothing is bulk-downloaded. Each scan:

1. sends one `POST https://api.osv.dev/v1/querybatch` per 1000 installed
   packages (name and version, in the distro's OSV ecosystem: `Debian:12`,
   `Ubuntu:22.04:LTS`, `Alpine:v3.19`, `Rocky Linux:9`, `AlmaLinux:8`,
   `Red Hat:enterprise_linux:9::baseos|appstream`), following
   `next_page_token`. Debian, Ubuntu and Alpine are queried by source
   package (`dpkg ${source:Package}` / `${source:Version}`, apk origin),
   Rocky by source RPM name, Alma and RHEL by binary name; RPM versions
   carry the epoch (`1:3.0.7-28.el9`). OSV carries the DSA/DLA, Debian
   tracker, USN, Alpine secdb, RLSA/ALSA and RHSA data;
2. fetches `GET /v1/vulns/{id}` only for the advisories that hit, 8 at a
   time, deduplicated, and reuses a cached advisory while its `modified`
   stamp is unchanged;
3. on RHEL-family hosts, fetches Red Hat's per-CVE record for each matched
   CVE (`redhat` source: severity, fixed NEVRAs, and `package_state` for the
   Red Hat judge, one fetch per CVE per `cache_ttl`);
4. asks NVD by id (`?cveId=`) only for matched CVEs that no other source
   scored. NVD's limits are honoured (5 requests / 30 s without an API key,
   50 with one) together with `nvd_max_per_run` and a time budget; the
   rest are looked up on later scans from where the cache left off.

The results go through the normal matcher (version comparison, module
streams, distro-beats-NVD), the applicability judges and severity
enrichment, so fixed versions still become remediation commands.

Caches live in `<cache_dir>/lookup/` (`osv.json`, `nvd.json`) and
`<cache_dir>/redhat/details/`. On a 159-package Debian 12 host the cache
was 0.3 MB after a scan. Entries not seen for 30 days are dropped.

If a lookup fails (after the HTTP retries), the report says the CVE section
is **incomplete** (JSON `data_sources.complete: false` with reasons, a red
banner in the PDF), `lyncd -once` exits 3 and `run.sh` exits 5. A distro
OSV has no data for (Fedora, Oracle Linux, CentOS Stream, SUSE) is reported
the same way rather than as a clean host; use `mode: full` with the distro
feed there.

**Privacy.** Lookup mode sends the names and versions of installed
packages (and of application components found by the
[inventory](INVENTORY.md)) to `api.osv.dev`, and CVE ids to
`services.nvd.nist.gov` and `access.redhat.com`. Nothing else about the
host is sent. If that is not acceptable, use `mode: full`: then only bulk
files are downloaded and nothing host-specific leaves the machine.

### `mode: full`

The original behaviour: every source in `sources[]` bulk-downloads on
`sync_interval` into `cache_dir/<source>/` (about 300 MB on a Debian host:
the Debian tracker JSON is 80 MB, the OSV ecosystem export 41 MB and is
held in memory, and NVD's 30-day window without an API key took 44
minutes). Use it for air-gapped mirrors or when lookups are not allowed.
`lyncd -feed-mode full` and `run.sh --full-feeds` select it for one run.

- **`sync_interval`** — how often the daemon refreshes the bulk feeds.
- **`sources[]`** — built-in names:
  - `redhat` — full: Red Hat Security Data API summary (rolling 365-day
    window, RPM fixes only). Lookup: per-CVE records for matched CVEs.
  - `osv` — full: OSV.dev bulk export for the host's ecosystem. Lookup: the
    query API (the main source in lookup mode).
  - `nvd` — full: distro-agnostic CPE ranges for a 30-day (120 with a key)
    window. Lookup: by CVE id for severity enrichment.
  - `debian`, `ubuntu`, `alpine` — full: the distro's bulk feed. Lookup:
    served by `osv`.

### Package-manager cross-check

With `local_check: true` (default) every full-host scan also asks the
package manager which security updates it would install, from its cached
metadata: `dnf -C -q updateinfo list --security` (or `yum -C ... security`)
on RPM hosts, `apt-get -s -o Debug::NoLocking=1 dist-upgrade` filtered to
`*-security` suites on Debian/Ubuntu. It never installs anything. Then:

- a CVE finding whose package (or a package built from the same source)
  has a pending security update is confirmed in its evidence, with the
  advisory id on RPM hosts;
- a CVE finding with a fixed version but no pending update is flagged
  ("metadata may be stale, or the fix is not in the configured
  repositories yet");
- a pending security update that no lookup explained becomes its own
  finding, `pkgmgr:security-update:<package>`.

`local_refresh: true` runs `dnf makecache` / `apt-get update` first. That
writes to the package manager's cache directory, so it is opt-in. Alpine
has no security pocket and is skipped.

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

In lookup mode the key raises the NVD rate limit and the per-run cap
(10 -> 200 lookups).

### Initial sync skip (full mode)

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

## `inventory`

```yaml
inventory:
  enabled: true
  containers: false      # list running docker/podman containers and inspect their images
  roots: []              # replace the default search roots (globs allowed)
  skip_paths: []         # path prefixes never entered
  time_budget: 2m
```

Full-host scans (daemon and `lyncd -once`) run the application inventory
after the rules engine: components installed outside the package manager
(lockfiles, site-packages, jars, Go/Rust binaries, WordPress) are looked
up on OSV.dev with the same client as the OS packages, and hits become CVE
findings. The JSON report gets an `inventory` section with the component
list and counts, the PDF a short summary. Walk limits and what is never
entered are in [`INVENTORY.md`](INVENTORY.md). `lyncd -sources none`
turns it off (no network lookups at all).

## `notify`

Off by default. When enabled, the daemon sends a message after a full
scan whenever the findings at or above `min_severity` changed:

- **new**: a finding that wasn't there before (a new CVE affecting an
  installed package, a new configuration issue);
- **fix_available**: a finding that had no fixed version now has one;
- **resolved**: a finding that disappeared. Never sent for CVE findings
  when the scan's CVE data was incomplete (a failed lookup is not a patch).

Each channel keeps its own record in `state_file`, so a finding is sent
once per channel, a channel that was down catches up on the next scan
(it gets the current state, not a backlog), and a new channel or a changed
`min_severity` starts with a one-off **baseline** message listing what is
currently open. `digest` adds a periodic summary of everything open.

```yaml
notify:
  enabled: true
  min_severity: high          # critical | high | medium | low | info | unknown
  events: [new, fix_available, resolved]
  digest: 0                   # e.g. 24h or 168h; 0 = off
  state_file: /var/lib/lync/notify-state.json
  email:
    enabled: true
    host: smtp.example.com
    port: 587                 # default 587 (starttls), 465 (tls), 25 (none)
    tls: starttls             # starttls | tls (implicit) | none (local relay only)
    username: lync@example.com
    password_file: /etc/lync/smtp.pass   # or password_env: LYNC_SMTP_PASSWORD
    from: "Lync <lync@example.com>"
    to: [ops@example.com, security@example.com]
    attach_pdf: true          # attach the scan's PDF (up to 10 MB)
    timeout: 30s
  webhooks:
    - name: ops-slack
      type: slack             # generic | slack | discord | teams
      url_file: /etc/lync/slack.url      # or url / url_env
    - name: ops-discord
      type: discord
      url_env: LYNC_DISCORD_WEBHOOK
    - name: ops-teams
      type: teams             # Workflows "post to a channel when a webhook request is received", or an O365 connector URL
      url_file: /etc/lync/teams.url
    - name: siem
      type: generic
      url: https://siem.example.com/hooks/lync
      secret_file: /etc/lync/webhook.secret   # HMAC-SHA256 signing key (or secret_env)
      timeout: 15s
```

Secrets (SMTP password, chat webhook URLs, which embed a token, and HMAC
keys) can come from a file (`chmod 600`) or an environment variable (set it
with `systemctl edit lync`, `Environment=`). They are read when a message
is sent and never logged: errors name only the webhook's host, and the
webhook HTTP client bypasses the audit transport. Plain SMTP without
STARTTLS is refused unless `tls: none` is set; PLAIN auth needs TLS (or
localhost).

Messages contain the host name, OS, the changed findings (CVE, package,
installed and fixed version, CVSS, per-finding fix), package-manager
commands for the affected packages (`dnf upgrade --refresh ...`,
`apt-get update && apt-get install --only-upgrade ...`, `apk upgrade ...`),
severity totals, a warning when the CVE data was incomplete, and the
report path on the host. Email is multipart text + HTML. Webhook POSTs are
retried (3 attempts, backoff, `Retry-After` honoured) on network errors,
429 and 5xx; other 4xx fail at once.

**Generic webhook schema** (`Content-Type: application/json`,
`User-Agent: lync/<version>`, `X-Lync-Event: changes|baseline|digest|test`):

```json
{
  "schema": "lync.notification/v1",
  "event": "changes",
  "host": "web1", "os": "Debian GNU/Linux 12 (bookworm)",
  "generated": "2026-10-21T08:00:00Z",
  "summary": "[lync] web1: 1 new, 1 resolved (worst: Critical)",
  "min_severity": "high",
  "counts": {"total": 139, "critical": 12, "high": 62, "medium": 54, "low": 8, "unknown": 3},
  "new": [{"id": "CVE-2026-0001:libssl3:amd64", "severity": "Critical", "category": "cve",
           "title": "CVE-2026-0001 affects libssl3:amd64", "cve": "CVE-2026-0001",
           "package": "libssl3:amd64", "installed": "libssl3:amd64-3.0.15-1~deb12u1.amd64",
           "fixed_in": "3.0.17-1~deb12u2", "cvss": 9.8, "source": "osv",
           "remediation": "update libssl3:amd64 to 3.0.17-1~deb12u2 or later"}],
  "fix_available": [],
  "resolved": [{"id": "...", "severity": "High", "cve": "...", "package": "..."}],
  "current": [],
  "remediation_commands": ["apt-get update && apt-get install --only-upgrade libssl3"],
  "report": {"json": "/var/lib/lync/reports/lync-....json", "pdf": "/var/lib/lync/reports/lync-....pdf"},
  "data_sources": {"mode": "lookup", "complete": true, "sources": [...]}
}
```

`current` is filled for `baseline` and `digest` events. With a
`secret_file`, two headers are added:

```
X-Lync-Timestamp:     1792569600
X-Lync-Signature-256: sha256=<hex HMAC-SHA256(secret, timestamp + "." + raw body)>
```

Verify by recomputing the HMAC over the timestamp, a dot and the raw body
bytes, comparing in constant time, and rejecting old timestamps (replay):

```python
mac = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
ok = hmac.compare_digest("sha256=" + mac, sig) and abs(time.time() - int(ts)) < 300
```

Slack gets `text` + Block Kit blocks, Discord an embed coloured by the
worst severity, Teams an Adaptive Card 1.4 message. Chat messages list up
to 15 findings per section; email up to 200.

`lync notify test [-config /etc/lync/lync.yaml]` sends a test message to
every configured channel (even with `enabled: false`) and prints `sent` or
the error per channel; it exits 1 if any failed. It needs no daemon.

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
  mode: full                 # NVD alone only makes sense with bulk sync
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
