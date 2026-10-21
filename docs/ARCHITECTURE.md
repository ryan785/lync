# Architecture

Lync is one Go binary (`lyncd`) running as one systemd service. There is
no helper process, no companion timer unit, no separate scan worker. The
daemon owns its own scheduler, IPC server, monitor goroutine, and feed
fetchers. The `lync` CLI is a stateless client that talks to the daemon
over a Unix domain socket.

## Data flow per scan

```
                              +---------------------+
                              | Internal scheduler  |
                              | scan tick / sync tick|
                              +----------+----------+
                                         |
                                         v
+--------+   facts   +---------+   vulns   +---------+   keep / drop   +----------+
|collector|--------->| matcher |---------->| applic. |---------------->|  rules   |
| (rpm,   |          |  (CVE   |          | engine  |                 | (host    |
|  dpkg,  |          |  match) |          | (judges |                 | config + |
|  apk)   |          +---------+          |  vote)  |                 |  monitor)|
+--------+               ^                +---------+                 +----+-----+
                         |                                                  |
                         | cached vulns.json per source                    |
                         |                                                  v
                  +------+------+                                    +----------+
                  | feed sources |                                   | reporter |
                  | (NVD, RHEL,  |                                   | JSON     |
                  | Debian, Ubuntu                                   | then PDF |
                  | OSV, Alpine) |                                   +----------+
                  +-------------+
```

Steps in order:

1. **Collector** reads the host: OS via `/etc/os-release`, kernel via
   `uname`, packages via `rpm -qa` / `dpkg-query` / `apk info` based on the
   detected package manager, running services via
   `systemctl list-units --type=service --state=running` plus
   `systemctl show -p FragmentPath` + `rpm -qf` (RPM hosts) to map each
   service to the package that owns its unit file. Returns `*collector.Facts`.

2. **Matcher** walks every cached `Vulnerability` from every feed source,
   filters by distro+version, compares installed NEVR against the
   per-distro fixed version, and emits one `finding.Finding` per
   (CVE, package) pair that fails the comparison. Findings are
   deduplicated by `(CVE, package)`, keeping the highest-priority source
   (Red Hat > Debian/Ubuntu/SUSE/Alpine > OSV > NVD).

3. **Applicability engine** consults every per-distro judge whose
   `AppliesTo(os)` returns true. Each judge returns one of
   `Affected / NotAffected / DeferredOrWontFix / Unknown`. A finding is
   dropped if any judge returns a status listed in
   `applicability.suppress_on` (default: `not_affected`,
   `deferred_or_wontfix`). This catches the case where NVD's upstream
   CPE matching produces a finding the distro has explicitly evaluated
   and decided doesn't apply.

4. **Rules engine** runs the six non-CVE checks (hardening, sshd,
   accounts, filesystem, network, EOL) concurrently and appends their
   findings to the CVE-derived list. Rules run **only on full-host scans**;
   scoped scans (`lync scan -package openssh`) skip them.

5. **Monitor drain** pulls accumulated file-integrity findings from the
   inotify watcher into the report.

6. **Reporter** computes the `ImpactSummary` (severity counts, kernel
   CVE list, active-services-affected, highest CVSS), writes the
   canonical JSON file, then renders the PDF by reading that JSON back.
   PDF is a pure function of JSON — `lync render <json>` produces a
   byte-identical file.

## Daemon process model

The daemon's main goroutine sets up the world and blocks on the context.
Goroutines spawned during `Run`:

| Goroutine | Started in | Job |
|---|---|---|
| `ipc.Serve` | `daemon.Run` | accept CLI connections, dispatch commands |
| `scheduler.Run` | `daemon.Run` | tick scan/sync timers, dispatch to job functions |
| `maybeInitialSync` | `daemon.Run` | one-shot startup sync if cache is stale |
| `monitor.loop` | `monitor.Start` | drain inotify events, emit runtime findings |
| `runScan(scope)` | per-scan, ad hoc | full pipeline for one scan |
| `runSync` | per-sync, ad hoc | feed sync for all enabled sources |

Each scan and sync registers a `RunningJob` in the daemon's `running`
map (snapshot returned by `lync status`). Scoped scans triggered by the
CLI bypass the scheduler entirely — the IPC handler launches
`runScan(d.ctx, scope)` directly because the scheduler's trigger channel
carries no payload.

## Feed sources

| Source | Bulk URL pattern | Scope |
|---|---|---|
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | universal (CPE matching) |
| Red Hat | `access.redhat.com/hydra/rest/securitydata/cve.json` summary + per-CVE detail | RHEL family |
| Debian | `security-tracker.debian.org/tracker/data/json` (one big tree) | Debian only |
| Ubuntu | `ubuntu.com/security/notices.json` (paginated USNs) | Ubuntu only |
| Alpine | `secdb.alpinelinux.org/v<ver>/main.json` + `community.json` | Alpine only |
| OSV | `osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip` | host-detected ecosystem |

All sources implement `feed.Source`:

```go
type Source interface {
    Name() string
    Sync(ctx, *Store, *slog.Logger) error
    Vulnerabilities(*Store) ([]Vulnerability, error)
}
```

`Store` is an on-disk cache rooted at `feed.cache_dir`. Each source
writes `<source>/vulns.json` and `<source>/manifest.json`. Per-CVE detail
data (RedHat, Ubuntu judges) lives under `<source>/details/<CVE>.json`.

## Applicability judges

Each judge implements `applicability.Judge`:

```go
type Judge interface {
    Name() string
    AppliesTo(os collector.OSInfo) bool
    Evaluate(ctx, cveID, pkgName, *Facts) (Verdict, error)
}
```

| Judge | Source of truth | Lookup |
|---|---|---|
| Red Hat | `cve/<id>.json` detail | `package_state[]` for host RHEL major + `affected_release[]` with shipped-NEVRA comparison |
| Debian | Cached `feed/debian/vulns.json` | In-memory `(CVE, distro, pkg) -> status` index |
| Ubuntu | `cves/<id>.json` detail | `packages[].statuses[release_codename]` |
| SUSE | Stub | Returns Unknown — Phase 2+ |
| Alpine | Stub | Returns Unknown — secdb is presence-based, no judgment beyond what the matcher already does |

A finding survives the applicability filter unless **any** judge returns
a verdict listed in `suppress_on`. If every judge says Unknown the
finding is kept (we don't have enough evidence to drop it).

## Rules engine

Each rule implements `rules.Rule`:

```go
type Rule interface {
    Name() string
    Run(ctx, *Facts, *slog.Logger) []finding.Finding
}
```

Rules run concurrently. A panicking rule logs and yields no findings;
one bad rule doesn't sink a scan.

The bundled rules are described in [`docs/EXTENDING.md`](EXTENDING.md).
The Finding shape is identical to CVE findings — categories distinguish
them (`hardening`, `config`, `filesystem`, `network`, `eol`).

## Monitor

`Monitor.Start` baselines every regular file under the configured paths
(walks directories once) and registers each path with `fsnotify`. On
event:

1. Re-fingerprint the path (mode + size + SHA-256 if ≤ 4 MiB).
2. Compare against the stored baseline.
3. If content or mode actually changed, emit a `runtime` finding into
   the in-memory `pending` slice.
4. Update the baseline so subsequent events compare against the new state.

`Monitor.Drain` is called by the daemon at each scan to move pending
findings into the report. Spurious events (an editor's atomic-rename
producing a Create event but the new file matches the old hash) are
filtered out by the hash comparison.

## Severity and source priority

The matcher records each `Vulnerability.Source` and the dedup logic
prefers higher-priority sources when the same `(CVE, package)` appears
in multiple feeds:

```go
func sourcePriority(source string) int {
    switch source {
    case "redhat", "debian", "ubuntu", "suse", "alpine":
        return 2
    case "osv":
        return 1
    }
    return 0
}
```

So when Red Hat marks `CVE-2026-31789` as Low and NVD scores it 9.8,
Lync uses Red Hat's view.

Beyond that dedup, three rules shape matching (all in `matcher.Match`):

- **Source-package fallback.** A feed name with no installed binary of
  that name is looked up as a *source* package (SRPM name / dpkg Source).
  NVD's CPE product `php` therefore matches a host that only has
  `php-fpm`/`php-cli`/`php-common`; one finding is emitted on the
  alphabetically first binary, with "matched via source package" in the
  evidence.
- **Module streams.** For module-built RPMs (`.module+el8...` releases),
  candidate fixes are narrowed to those whose version shares the longest
  dotted prefix with the installed version, so a php 8.0 host is judged
  only by the php:8.0 stream's fix. If only other streams have a fix, the
  remediation says to switch streams.
- **Distro "patched" beats NVD.** If any distro-scoped source (non-`*`
  distro filter, concrete fixed version) says the installed build is
  already fixed, an NVD finding for the same (CVE, package) is dropped. The exception is when source names disagree on
package: pre-dedup, both findings exist, and the applicability engine
must catch the NVD finding via the RedHatJudge looking at
`package_state[]`.

## CLI color scheme

| Element | Color |
|---|---|
| Title (`lync 0.1.0`) | bold cyan |
| Daemon "running" | green |
| Timestamps, paths, sources | cyan |
| Numeric counts | bold |
| Section headers | bold |
| Scan job kind | cyan |
| Sync job kind | yellow |
| Custom scopes (`pkg=openssh`) | magenta |
| `all` / `idle` / `never` | dim |
| Errors | red |

TTY detected via `os.Stdout.Stat() & os.ModeCharDevice`. Honors `NO_COLOR`
env var.

## Code layout

```
cmd/
  lyncd/main.go          daemon entry: load config, wire daemon, block on signals
  lync/main.go           CLI entry: parse global flags, dispatch subcommand
  lync/color.go          ANSI helpers (TTY-detection lives here)

internal/
  collector/             host fact gathering (rpm.go, dpkg.go, apk.go, services.go, ...)
  feed/                  vuln data sources (one .go per provider)
  matcher/               CVE matching + RPM-aware version comparison
  applicability/         per-distro judges that drop or downgrade findings
  rules/                 non-CVE rules engine (hardening.go, ssh_config.go, ...)
  monitor/               fsnotify file-integrity watcher
  reporter/              JSON canonical, PDF rendered from JSON
  ipc/                   unix-socket protocol + server + client
  scheduler/             internal cron for scan and sync timers
  daemon/                wires everything; owns RunningJob state
  config/                YAML config loader
  logging/               slog setup
  finding/               the Finding type — shared across all producers

packaging/
  systemd/lync.service
  config/lync.yaml
  scripts/                 package scripts: postinstall (enable + start), preremove,
                           postremove, postupgrade (apk)
nfpm.yaml                  .deb / .rpm / .apk definition (built by `make release`)
install.sh                 one-line installer: downloads + installs the package
```

The `internal/` enforcement keeps the public API surface limited to
`cmd/`; only the binaries can reach in, so future Lync versions can
restructure internals without breaking downstream packages.
