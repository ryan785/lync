# Extending Lync

Three places to plug new code in: a new **feed source**, a new
**applicability judge**, or a new **rule**. All three follow the same
pattern — implement an interface, register the type, ship a config knob.

---

## Adding a feed source

A feed source pulls vulnerability data from somewhere and writes a
normalized `Vulnerability` list into the on-disk cache. The matcher
consumes the cache; the source itself doesn't run during scans.

### Interface

```go
// internal/feed/types.go
type Source interface {
    Name() string
    Sync(ctx context.Context, store *Store, log *slog.Logger) error
    Vulnerabilities(store *Store) ([]Vulnerability, error)
}
```

### Skeleton

```go
// internal/feed/myfeed.go
package feed

import (
    "context"
    "encoding/json"
    "fmt"
    "log/slog"
    "net/http"
    "time"
)

type MyFeedSource struct {
    client *http.Client
}

func NewMyFeed() *MyFeedSource {
    return &MyFeedSource{client: &http.Client{Timeout: 60 * time.Second}}
}

func (s *MyFeedSource) Name() string { return "myfeed" }

func (s *MyFeedSource) Sync(ctx context.Context, store *Store, log *slog.Logger) error {
    log.Info("myfeed sync starting")

    resp, err := s.client.Get("https://example.com/cves.json")
    if err != nil { return err }
    defer resp.Body.Close()

    var raw []someProviderFormat
    if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
        return err
    }

    vulns := make([]Vulnerability, 0, len(raw))
    for _, r := range raw {
        vulns = append(vulns, Vulnerability{
            ID:          r.CVEID,
            Source:      s.Name(),
            Severity:    r.Severity,
            Description: r.Description,
            CVSS:        r.CVSS,
            Affects: []AffectedPackage{{
                Distro:       "debian:12",   // or whatever applies
                Name:         r.Package,
                FixedVersion: r.FixedVersion,
                Status:       r.Status,
            }},
        })
    }
    log.Info("myfeed sync complete", "vulns", len(vulns))
    return store.PutVulns(s.Name(), vulns)
}

func (s *MyFeedSource) Vulnerabilities(store *Store) ([]Vulnerability, error) {
    return store.GetVulns(s.Name())
}
```

### Register

Add a `case` to `internal/feed/build.go`:

```go
case "myfeed":
    sources = append(sources, NewMyFeed())
```

Enable in `lync.yaml`:

```yaml
feed:
  sources:
    - name: myfeed
      enabled: true
```

### Conventions

- Always set `Vulnerability.Source` to your `Name()` so the matcher's
  source-priority dedup logic works.
- Use `Distro` filters in `Affects[]` — see
  [`docs/CONFIGURATION.md`](CONFIGURATION.md) for the format.
- `Status` should hold the provider's raw vocabulary so judges can
  interpret it.
- If your provider has a 120-day-style window, default conservatively
  without an API key and bump it up when one is present (see how
  `feed/nvd.go` does it).
- Cache everything to disk via `Store.PutVulns`. Don't keep all data in
  memory — the daemon's RSS budget is tight.

---

## Adding an applicability judge

A judge decides whether a finding the matcher already emitted should
survive or be suppressed. Typically one judge per distro family.

### Interface

```go
// internal/applicability/types.go
type Judge interface {
    Name() string
    AppliesTo(os collector.OSInfo) bool
    Evaluate(ctx context.Context, cveID, pkgName string, facts *collector.Facts) (Verdict, error)
}
```

### Skeleton

```go
// internal/applicability/myjudge.go
package applicability

import (
    "context"
    "github.com/ryan785/lync/internal/collector"
)

type MyJudge struct {
    // network client, cache dir, in-memory index, etc.
}

func NewMyJudge() *MyJudge { return &MyJudge{} }

func (j *MyJudge) Name() string { return "myjudge" }

func (j *MyJudge) AppliesTo(os collector.OSInfo) bool {
    return os.ID == "mydistro"
}

func (j *MyJudge) Evaluate(ctx context.Context, cveID, pkgName string, facts *collector.Facts) (Verdict, error) {
    // Look up your provider's stance for (cveID, pkgName, facts.OS).
    status, err := j.lookup(ctx, cveID, pkgName, facts.OS)
    if err != nil {
        return Verdict{Status: StatusUnknown, Judge: j.Name()}, err
    }
    switch status {
    case "not-affected":
        return Verdict{Status: StatusNotAffected, Judge: j.Name(),
            Reason: "MyDistro: not affected"}, nil
    case "ignored", "deferred":
        return Verdict{Status: StatusDeferredOrWontFix, Judge: j.Name(),
            Reason: "MyDistro: " + status}, nil
    case "affected":
        return Verdict{Status: StatusAffected, Judge: j.Name(),
            Reason: "MyDistro: affected"}, nil
    }
    return Verdict{Status: StatusUnknown, Judge: j.Name()}, nil
}
```

### Two implementation patterns

- **Cached-bulk** (Debian): the paired feed source pulled all data;
  the judge builds an in-memory index from the cached vulns on first
  Evaluate. Cheap once warmed; works offline. See
  [`internal/applicability/debian.go`](../internal/applicability/debian.go).
- **Lazy per-CVE** (Red Hat, Ubuntu): the judge fetches per-CVE detail
  on demand and caches the response on disk indefinitely. Slower first
  scan, fast afterwards. Use this pattern when the bulk feed doesn't
  carry the curated stance you need. See
  [`internal/applicability/redhat.go`](../internal/applicability/redhat.go).

### Register

Add to `internal/daemon/daemon.go` `buildApplicabilityEngine`:

```go
judges := []applicability.Judge{
    applicability.NewRedHatJudge(rhCacheDir),
    applicability.NewDebianJudge(store),
    applicability.NewUbuntuJudge(ubCacheDir),
    applicability.NewMyJudge(),         // <-- here
    ...
}
```

### Verdicts

| Status | Effect (default config) |
|---|---|
| `StatusAffected` | keep finding |
| `StatusNotAffected` | suppress |
| `StatusDeferredOrWontFix` | suppress |
| `StatusUnknown` | keep (fall through to other judges) |

Operators can override `suppress_on` in `lync.yaml` to change which
statuses drop findings.

---

## Adding a rule

A rule produces findings from host configuration, not feed data. Each
rule is independent — runs concurrently, panics safely.

### Interface

```go
// internal/rules/rules.go
type Rule interface {
    Name() string
    Run(ctx context.Context, facts *collector.Facts, log *slog.Logger) []finding.Finding
}
```

### Skeleton

```go
// internal/rules/myrule.go
package rules

import (
    "context"
    "log/slog"
    "time"
    "github.com/ryan785/lync/internal/collector"
    "github.com/ryan785/lync/internal/finding"
)

type MyRule struct{}

func NewMyRule() *MyRule { return &MyRule{} }

func (r *MyRule) Name() string { return "myrule" }

func (r *MyRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger) []finding.Finding {
    // Do whatever check you need. Read /proc, parse config files, query
    // running services via systemctl, walk a filesystem subtree, etc.
    var out []finding.Finding
    if !somethingGoodIsTrue() {
        out = append(out, finding.Finding{
            ID:          "myrule:bad-thing",
            Category:    finding.CategoryConfig,   // or another category
            Severity:    finding.SeverityHigh,
            Title:       "The bad thing is happening",
            Evidence:    "concrete observation a human can verify",
            Remediation: "one-line fix the operator can copy/paste",
            DetectedAt:  time.Now(),
            Source:      "lync-rules",
        })
    }
    return out
}
```

### Register

Add to `internal/rules/rules.go` `DefaultRules()`:

```go
func DefaultRules() []Rule {
    return []Rule{
        NewHardeningRule(),
        NewSSHConfigRule(),
        NewAccountRule(),
        NewFilesystemRule(),
        NewNetworkRule(),
        NewEOLRule(),
        NewMyRule(),         // <-- here
    }
}
```

### Categories

`internal/finding/finding.go` defines:

| Category | Existing producers |
|---|---|
| `cve` | matcher |
| `config` | sshd, sudoers, accounts |
| `eol` | eol rule |
| `hardening` | hardening rule (sysctl) |
| `filesystem` | filesystem rule |
| `network` | network rule |
| `tls` | (reserved — no rule yet) |
| `runtime` | monitor |

Pick the closest fit or add a new constant if the rule's findings
genuinely don't belong in any existing category.

### Good-citizen tips

- Cap work. Don't walk the whole filesystem; pick the smallest
  meaningful root.
- Be fast. Rules run every scan — if yours takes seconds, it's a problem.
- Skip silently when the data source isn't available (config file
  missing, optional command not installed). Don't produce false
  "command failed" findings.
- Severity calibration matters. `Critical` means "act today";
  `High` means "act this week". If everything is High, nothing is.
- Set `Source: "lync-rules"` so the reporter can filter rule-derived
  findings.

---

### Checks built on `rules.Host` (preferred for new checks)

New checks should not touch `os` or `exec` directly. Use the per-scan
`Host` from `opts.host()`:

```go
func init() {
    register(CheckInfo{ID: "foo:bar", Rule: "foo", Severity: finding.SeverityHigh,
        Description: "One line for `lync checks`"})
}

func (r *FooRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
    h := opts.host()
    if !opts.on("foo:bar") {             // honours rules.disable / rules.enable
        return nil
    }
    b, err := h.ReadFile("/etc/foo.conf") // host path; mapped under rules.root
    if err != nil {
        return nil                        // missing file/tool = no finding, never a panic
    }
    out, _ := h.Run(ctx, "footool", "-q") // 20s timeout; faked in tests
    ...
    return []finding.Finding{mkFinding(h, "foo:bar", key, finding.CategoryConfig, finding.SeverityHigh,
        "Title", "evidence (never secret values)", "exact remediation command", "https://reference")}
}
```

Rules for checks:

- Read-only. No writes, no service restarts. Anything that executes inside
  another context (e.g. `docker exec`) must be `DefaultOff: true`.
- Stable IDs: `<check-id>:<key>` where key is a path, port, unit or name
  that doesn't change between scans.
- Every finding carries evidence, a remediation command and, where one
  exists, a reference URL. Secrets: key names only.
- Shared lookups are memoized per scan: `h.Listeners(ctx)` (ss),
  `h.Accounts()`/`h.Groups()`, `h.loadNginx(ctx)`, `h.webRoots(ctx)`,
  `phpPools(h)`. Permission helpers: `h.Stat`, `h.WritableBy`,
  `h.WorldReachable`.

Tests are table-driven over a fixture root (`newFixture(t)` in
`internal/rules/testhost_test.go`): write files with `fx.file(path, body)`,
set POSIX mode/owner with `fx.meta(path, mode, uid, gid)`, fake tools with
`fx.cmd("ss -H -tulnp", output)`, symlinks via `fx.h.Links`. They run the
same on Windows and Linux. `requireShape` asserts every finding has the
shared fields and a catalog entry. Windows Defender quarantines fixture
files that look like real web shells (e.g. `system($_GET[...])`), so keep
such fixtures benign-looking.

## Adding a collector

Less common but useful when supporting a new package manager. Each
collector lives in `internal/collector/` and is wired through
`detectPackageManager` in `collector.go`.

```go
// internal/collector/portage.go (hypothetical Gentoo support)
package collector

func readPortagePackages(ctx context.Context) ([]Package, error) {
    // qlist -Iv or eix-installed --format json...
    // return []Package{{Name, Version, Release, Arch, Manager: "portage"}}
}
```

Then in `collector.go`:

```go
func detectPackageManager(osInfo OSInfo) string {
    ...
    if osInfo.ID == "gentoo" {
        return "portage"
    }
    ...
}

func readPackages(ctx context.Context, osInfo OSInfo, log *slog.Logger) ([]Package, error) {
    switch detectPackageManager(osInfo) {
    case "rpm":     return readRPMPackages(ctx)
    case "dpkg":    return readDpkgPackages(ctx)
    case "apk":     return readApkPackages(ctx)
    case "portage": return readPortagePackages(ctx)
    }
    return nil, nil
}
```

You'll likely also want a Gentoo feed source (GLSA) and judge to go
with the collector.

---

## Testing

Each new component should ship a `_test.go`:

- **Feed sources**: feed a fixture JSON byte slice into the parse
  function, assert the resulting `Vulnerability` slice matches
  expectations. Don't make tests depend on the live network.
- **Judges**: feed a fixture detail JSON into the judge's `Evaluate`,
  assert verdict transitions.
- **Rules**: read fixture files from `testdata/`, run the rule, assert
  finding count and severity.
- **Collectors**: see `internal/collector/dpkg_test.go` and
  `apk_test.go` for the pattern — parse a `strings.NewReader`-wrapped
  fixture of the command's output.

Run with `make test` (or `go test ./...`). CI should also `go vet ./...`.
