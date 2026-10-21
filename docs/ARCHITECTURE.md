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

Steps in order (in lookup mode, the default, the "feed sources" box is a
set of API lookups made during the scan: see [Feed modes](#feed-modes)):

1. **Collector** reads the host: OS via `/etc/os-release`, kernel via
   `uname`, packages via `rpm -qa` / `dpkg-query` / `apk info` based on the
   detected package manager, running services via
   `systemctl list-units --type=service --state=running` plus
   `systemctl show -p FragmentPath` + `rpm -qf` (RPM hosts) to map each
   service to the package that owns its unit file. Returns `*collector.Facts`.

2. **Matcher** walks every `Vulnerability` (looked up for this scan, or
   cached by the bulk feeds in full mode),
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

   After the judges, `matcher.EnrichSeverity` fills severity/CVSS for
   findings whose winning source had none (OSV CVSS vectors, NVD), and
   the package-manager cross-check (`feed.local_check`) confirms findings
   against `dnf updateinfo` / `apt-get -s` and adds pending security
   updates nothing else explained.

4. **Rules engine** runs the non-CVE checks concurrently and appends
   their findings to the CVE-derived list: the Go rules (web exposure,
   PHP, access paths, runtimes, system state...) and the declarative
   check packs (`internal/checks/packs/*.yaml`, evaluated by
   `internal/rules/decl_*.go` on a pool of 8 workers). Each pack check is
   gated (`applies_if`), runs one read-only, time- and size-bounded
   probe, and ends as passed, failed, skipped (probe couldn't decide) or
   not applicable; the per-pack tally is written to the report as
   `check_coverage`. Rules run **only on full-host scans**; scoped scans
   (`lync scan -package openssh`) skip them.

   Then the **application inventory** (`internal/inventory`, full-host
   scans) collects components outside the package manager and looks them
   up through the same OSV client; hits are CVE findings.

5. **Monitor drain** pulls accumulated file-integrity findings from the
   inotify watcher into the report.

6. **Reporter** computes the `ImpactSummary` (severity counts, kernel
   CVE list, active-services-affected, highest CVSS), writes the
   canonical JSON file, then renders the PDF by reading that JSON back.
   PDF is a pure function of JSON — `lync render <json>` produces a
   byte-identical file. The JSON carries `data_sources` (mode, sources,
   request/cache/byte counts, packages checked, timestamp, `complete` and
   the reasons when it is not) and `inventory`.

7. **Notifications** (`notify.enabled`, daemon only): `internal/notify`
   diffs the findings at or above `notify.min_severity` against what each
   channel was last told (state file) and sends new / fix available /
   resolved / digest messages by SMTP or webhook.

## Upstream runtimes (Node.js)

Distro advisories only describe distro builds, and OSV.dev has no
ecosystem for runtime cores, so a Node.js installed with nvm, from a
tarball, from NodeSource or in a `node:` image was invisible to the CVE
section. `internal/upstream` covers it with the runtime project's own data.
A `Provider` detects installs on a `rules.Host`, fetches advisory data and
matches it into ordinary findings. Node.js is the first provider.

- **Detection.** Lync looks in these places:
  - running processes (`rules.ProcessExes`)
  - `~/.nvm`, fnm, volta, asdf and mise directories under `/root` and `/home/*`
  - `/usr/local/bin/node`, `/usr/local/n`, `/usr/local/lib/nodejs/*` and `/opt/*/bin/node`
  - NodeSource packages (an installed `nodejs` whose version contains `nodesource`)
  - `node:<x.y.z>` container images from the application inventory
  
  The version comes from the path or from `node --version`. Installs are
  deduplicated by their real path. A distro `/usr/bin/node` is skipped
  because distros backport fixes and stay on distro advisories.
- **Data.** Three small files are cached under
  `<cache_dir>/upstream/` and revalidated with `If-None-Match` /
  `If-Modified-Since`. A copy younger than an hour is reused with no
  request.
  - `nodejs.org/dist/index.json`: the `security` flag of each release.
  - `nodejs/security-wg` `vuln/core/index.json`: CVEs with node-semver
    vulnerable/patched ranges.
  - `nodejs/Release` `schedule.json`: EOL dates. They feed
    `runtime:eol-node` and `container:eol-base`, and the built-in table is
    the offline fallback.
- **Matching.**
  - `upstream:node-cve`: one finding per CVE whose vulnerable range
    contains the version and whose patched range does not. `fixed_in` is the
    first patched release on the install's major line. CVSS comes from the
    NVD-by-id lookup, or from the cached NVD feed in full mode.
  - `upstream:node-security-release`: a newer release on the same line is
    flagged `security` in `index.json`. This is the same-day signal. When
    CVE findings exist it is folded into them. It is kept only for a
    security release newer than every CVE fix that no security-wg entry
    names yet: the release-day gap.
  - A security-wg entry with no fix on the install's line is not reported,
    because `runtime:eol-node` covers EOL lines.
- **Distro exclusion.** NodeSource packages are removed from the facts
  given to the distro lookup and the matcher.
- **Scan order.** The daemon detects and fetches before the rules run, so
  the schedule reaches the EOL checks. It matches after the inventory, so
  image tags are included.
- **Data source.** Reports list the data source as `nodejs`. It follows
  `osv` unless `feed.sources` lists `nodejs`, so `-sources none` turns it
  off. A failed fetch while upstream installs exist marks the CVE section
  incomplete.

Finding shapes. Every finding has category `cve`, check pack `runtimes`
and a `source` that starts with `nodejs`:

| Check | ID | Package | Source |
|---|---|---|---|
| `upstream:node-cve` | `upstream:node-cve:<CVE>:<path>` | `node`, or `nodejs` for NodeSource | `nodejs-security-wg`, or `nodejs-security-wg+nvd` when NVD scored it |
| `upstream:node-security-release` | `upstream:node-security-release:<path>` | `node`, or `nodejs` for NodeSource | `nodejs-release` |

`<path>` is the binary path, or `image:<ref>` for a container image. The
text report groups these findings per binary under "Upgrade Node.js", not
in the OS package update command.

## Daemon process model

The daemon's main goroutine sets up the world and blocks on the context.
Goroutines spawned during `Run`:

| Goroutine | Started in | Job |
|---|---|---|
| `ipc.Serve` | `daemon.Run` | accept CLI connections, dispatch commands |
| `scheduler.Run` | `daemon.Run` | tick scan/sync timers, dispatch to job functions |
| `maybeInitialSync` | `daemon.Run` | full mode: one-shot startup sync if cache is stale |
| `maybeInitialScan` | `daemon.Run` | lookup mode: scan soon after start if the newest report is older than `scan.interval` |
| `watchPackages` | `daemon.Run` | inotify on the rpm/dpkg/apk database; debounced `scan` trigger (`scan.on_package_change`) |
| `monitor.loop` | `monitor.Start` | drain inotify events, emit runtime findings |
| `runScan(scope)` | per-scan, ad hoc | full pipeline for one scan |
| `runSync` | per-sync, ad hoc | feed sync for all enabled sources |

Each scan and sync registers a `RunningJob` in the daemon's `running`
map (snapshot returned by `lync status`). Scoped scans triggered by the
CLI bypass the scheduler entirely — the IPC handler launches
`runScan(d.ctx, scope)` directly because the scheduler's trigger channel
carries no payload.

## Feed modes

`feed.mode: lookup` (default) builds an `internal/lookup.Client` instead
of bulk `feed.Source`s. One scan:

```
installed packages --(source name, version, ecosystem)--> POST api.osv.dev/v1/querybatch  (1 req / 1000 pkgs, pages)
advisory ids hit   --(only ids whose "modified" changed)--> GET  api.osv.dev/v1/vulns/{id}  (8 parallel, cached)
        |
        v  osvToVulns: one Vulnerability per CVE in id/aliases/upstream, host ecosystem only,
        |  severity from distro label (Moderate/Important, Ubuntu priority, Debian urgency) and CVSS v3 vector
matcher.Match (candidates)
        |--> RHEL family: GET access.redhat.com/.../cve/{CVE}.json per matched CVE  (source "redhat", TTL cache,
        |    the same records the Red Hat judge reads)
        |--> NVD: GET ...?cveId=  only for matched CVEs nothing scored (5/30 s, cap, budget, 7-day cache)
        v
matcher.Match -> judges -> EnrichSeverity -> local cross-check -> rules -> inventory -> report
```

Every source returns a `feed.SourceStat`; together they are the report's
`feed.ScanSources`. A failed querybatch, failed detail fetches, failed
Red Hat or NVD lookups, or a distro OSV has no ecosystem for set
`complete: false` with a reason, so a report can never claim "0 findings"
when the lookups did not happen; `lyncd -once` then exits 3.

The OSV client (`feed.OSVLookup`: `QueryBatchEach`, `QueryBatch`,
`FetchRecords`, `GetRecordJSON`) is the only querybatch implementation;
`inventory.QueryOSV` wraps it for application components.

`feed.mode: full` keeps the bulk sources below, synced on
`feed.sync_interval` into `feed.cache_dir`.

## Feed sources (full mode)

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

## Notifications

`internal/notify` (daemon, after each full scan; `lync notify test` from
the CLI). Channels implement `Channel{Name, Send}`: SMTP (`net/smtp`,
STARTTLS or implicit TLS, PLAIN auth, multipart text+HTML, optional PDF)
and webhooks (generic JSON `lync.notification/v1` with optional
HMAC-SHA256 `X-Lync-Signature-256`, Slack blocks, Discord embed, Teams
Adaptive Card). Webhooks use their own HTTP transport so tokenised URLs
never reach the audit log; errors carry only the host. The state file keeps
one snapshot per channel (finding id -> severity, fixed version), so each
channel is told once, catches up after an outage, and new channels start
with a baseline. Missing CVE findings are not "resolved" when the scan's
CVE data was incomplete.

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
| Red Hat | `cve/<id>.json` detail (`feed.RedHatDetails`, TTL cache shared with lookups) | `package_state[]` for host RHEL major + `affected_release[]` with shipped-NEVRA comparison |
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
  feed/                  vuln data sources (one .go per provider), lookup clients
                         (osv_lookup, nvd_lookup, redhat_lookup), CVSS v3 scoring,
                         host ecosystem mapping, ScanSources
  lookup/                lookup-mode orchestration + package-manager cross-check
  notify/                email / webhook notifications and their state
  inventory/             application components outside the package manager
  upstream/              non-distro runtimes (Node.js) vs the runtime's own advisories
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
