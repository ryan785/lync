package applicability

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ryan785/lync/internal/audit"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/matcher"
)

const redhatDetailURL = "https://access.redhat.com/hydra/rest/securitydata/cve/%s.json"

// RedHatJudge looks up Red Hat's per-CVE detail (which the summary feed
// doesn't expose) and inspects package_state[] for an entry matching the
// host's RHEL major version + the package in the candidate finding.
type RedHatJudge struct {
	cacheDir string
	client   *http.Client

	mu       sync.Mutex
	inflight map[string]*sync.WaitGroup
	negCache map[string]time.Time // recent fetch failures, don't immediately retry
}

func NewRedHatJudge(cacheDir string) *RedHatJudge {
	return &RedHatJudge{
		cacheDir: cacheDir,
		client:   &http.Client{Timeout: 30 * time.Second},
		inflight: map[string]*sync.WaitGroup{},
		negCache: map[string]time.Time{},
	}
}

func (j *RedHatJudge) Name() string { return "redhat" }

// AppliesTo: any RPM-like distro that tracks Red Hat advisories.
func (j *RedHatJudge) AppliesTo(os collector.OSInfo) bool {
	switch os.ID {
	case "rhel", "rocky", "almalinux", "centos", "fedora", "ol":
		return true
	}
	for _, l := range os.IDLike {
		if l == "rhel" {
			return true
		}
	}
	return false
}

type redHatDetail struct {
	Name            string                  `json:"name"`
	ThreatSeverity  string                  `json:"threat_severity"`
	Statement       string                  `json:"statement"`
	PackageState    []redHatPackageState    `json:"package_state"`
	AffectedRelease []redHatAffectedRelease `json:"affected_release"`
}

type redHatPackageState struct {
	ProductName string `json:"product_name"`
	PackageName string `json:"package_name"`
	FixState    string `json:"fix_state"`
	CPE         string `json:"cpe"`
}

type redHatAffectedRelease struct {
	ProductName string `json:"product_name"`
	Package     string `json:"package"`
	Advisory    string `json:"advisory"`
	CPE         string `json:"cpe"`
}

func (j *RedHatJudge) Evaluate(ctx context.Context, cveID, pkgName string, facts *collector.Facts) (Verdict, error) {
	if cveID == "" || pkgName == "" {
		return Verdict{Status: StatusUnknown, Judge: j.Name()}, nil
	}
	d, err := j.detail(ctx, cveID)
	if err != nil {
		return Verdict{Status: StatusUnknown, Judge: j.Name()}, err
	}
	if d == nil {
		return Verdict{Status: StatusUnknown, Judge: j.Name()}, nil
	}

	major := rhelMajor(facts.OS)
	if major == "" {
		return Verdict{Status: StatusUnknown, Judge: j.Name()}, nil
	}
	productMatch := "Red Hat Enterprise Linux " + major

	// package_state is the curated "we evaluated this combination" data.
	for _, ps := range d.PackageState {
		if ps.ProductName != productMatch {
			continue
		}
		if !packageStateApplies(ps.PackageName, pkgName, facts.Packages) {
			continue
		}
		switch normalizeFixState(ps.FixState) {
		case "not affected":
			return Verdict{
				Status: StatusNotAffected,
				Judge:  j.Name(),
				Reason: fmt.Sprintf("Red Hat: %s for %s on %s", ps.FixState, ps.PackageName, ps.ProductName),
			}, nil
		case "will not fix", "out of support scope", "fix deferred":
			return Verdict{
				Status: StatusDeferredOrWontFix,
				Judge:  j.Name(),
				Reason: fmt.Sprintf("Red Hat: %s for %s on %s%s",
					ps.FixState, ps.PackageName, ps.ProductName, statementSuffix(d.Statement)),
			}, nil
		case "affected", "new", "investigation", "under investigation":
			return Verdict{Status: StatusAffected, Judge: j.Name(), Reason: ps.FixState}, nil
		}
	}

	// affected_release tells us Red Hat shipped a fix for this product +
	// package. Compare the shipped NEVRA against what's actually installed:
	// if installed >= shipped, the host is patched and any other source
	// (typically NVD doing pure upstream-CPE matching that ignores distro
	// backports) is wrong to flag this CVE.
	//
	// Red Hat lists fixes by *binary* package name. Many installed binaries
	// are subpackages built from the same source RPM (libcurl from curl,
	// libxml2-devel from libxml2, etc.). They share the patched code, so a
	// shipped fix on "curl" applies to the host's "libcurl" too. We treat
	// the released name as matching pkgName if either:
	//   (a) the names match directly (libcurl <-> libcurl)
	//   (b) any installed copy of pkgName has a Source whose base name
	//       matches the released name (libcurl with Source=curl-...src.rpm
	//       matches a fix on "curl")
	for _, ar := range d.AffectedRelease {
		if !strings.Contains(ar.ProductName, productMatch) {
			continue
		}
		releasedName, releasedNEVR, ok := parseFixNEVRA(ar.Package)
		if !ok {
			continue
		}
		if !packageNamesMatch(releasedName, pkgName) &&
			!installedSourceMatches(facts.Packages, pkgName, releasedName) {
			continue
		}
		installedNEVR := highestInstalledNEVR(facts.Packages, pkgName)
		if installedNEVR == "" {
			return Verdict{Status: StatusAffected, Judge: j.Name(),
				Reason: "shipped fix in " + ar.Advisory + " (installed copy not found)"}, nil
		}
		if matcher.CompareNEVR(installedNEVR, releasedNEVR) >= 0 {
			return Verdict{
				Status: StatusNotAffected,
				Judge:  j.Name(),
				Reason: fmt.Sprintf("patched by %s on %s (installed %s >= shipped %s)",
					ar.Advisory, ar.ProductName, installedNEVR, releasedNEVR),
			}, nil
		}
		return Verdict{
			Status: StatusAffected,
			Judge:  j.Name(),
			Reason: fmt.Sprintf("needs %s (installed %s < shipped %s)",
				ar.Advisory, installedNEVR, releasedNEVR),
		}, nil
	}

	return Verdict{Status: StatusUnknown, Judge: j.Name()}, nil
}

// installedSourceMatches returns true if any installed copy of pkgName was
// built from a source RPM whose base name matches releasedName. Used to tie
// Red Hat fix advisories (which name the *binary* package, e.g. "curl") to
// the subpackages a host actually has installed (e.g. "libcurl").
func installedSourceMatches(pkgs []collector.Package, pkgName, releasedName string) bool {
	for _, p := range pkgs {
		if p.Name != pkgName {
			continue
		}
		src := sourceRPMBaseName(p.Source)
		if src != "" && packageNamesMatch(releasedName, src) {
			return true
		}
	}
	return false
}

// sourceRPMBaseName extracts the package name from a SOURCERPM string.
//
//	"curl-7.76.1-35.el9_7.3.src.rpm"  -> "curl"
//	"glibc-2.34-231.el9_7.10.src.rpm" -> "glibc"
//
// Returns "" if the string isn't a recognizable SRPM filename.
func sourceRPMBaseName(src string) string {
	base := strings.TrimSuffix(src, ".src.rpm")
	if base == src {
		return ""
	}
	for i := 0; i < len(base)-1; i++ {
		if base[i] == '-' && base[i+1] >= '0' && base[i+1] <= '9' {
			return base[:i]
		}
	}
	return ""
}

// highestInstalledNEVR finds the maximum-versioned installed copy of pkgName.
// Returns "" if not installed. The matcher already dedupes by name keeping
// max, so usually there's only one — but we walk the list defensively in
// case this judge is called against an unfiltered Facts.
func highestInstalledNEVR(pkgs []collector.Package, pkgName string) string {
	var best string
	for _, p := range pkgs {
		if p.Name != pkgName {
			continue
		}
		nevr := p.NEVR()
		if best == "" || matcher.CompareNEVR(nevr, best) > 0 {
			best = nevr
		}
	}
	return best
}

// parseFixNEVRA splits Red Hat's "openssl-1:3.5.1-7.el9_7" into name +
// "epoch:version-release". Returns ok=false on malformed input.
func parseFixNEVRA(s string) (name, nevr string, ok bool) {
	for i := 0; i < len(s)-1; i++ {
		if s[i] != '-' {
			continue
		}
		j := i + 1
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j > i+1 && j < len(s) && s[j] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	// No "-N:" — fall back to "name-version-release" with no epoch.
	last := strings.LastIndex(s, "-")
	if last <= 0 {
		return "", "", false
	}
	second := strings.LastIndex(s[:last], "-")
	if second <= 0 {
		return s[:last], s[last+1:], true
	}
	return s[:second], s[second+1:], true
}

// detail fetches Red Hat's per-CVE JSON, caching on disk. Concurrent calls
// for the same CVE wait on a shared sync.WaitGroup so we don't refetch.
func (j *RedHatJudge) detail(ctx context.Context, cveID string) (*redHatDetail, error) {
	path := filepath.Join(j.cacheDir, cveID+".json")
	if data, err := os.ReadFile(path); err == nil {
		var d redHatDetail
		if err := json.Unmarshal(data, &d); err == nil {
			return &d, nil
		}
	}

	j.mu.Lock()
	if t, ok := j.negCache[cveID]; ok && time.Since(t) < 10*time.Minute {
		j.mu.Unlock()
		return nil, nil
	}
	if wg, ok := j.inflight[cveID]; ok {
		j.mu.Unlock()
		wg.Wait()
		// Try cache again — peer may have populated it.
		if data, err := os.ReadFile(path); err == nil {
			var d redHatDetail
			if err := json.Unmarshal(data, &d); err == nil {
				return &d, nil
			}
		}
		return nil, nil
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	j.inflight[cveID] = wg
	j.mu.Unlock()

	defer func() {
		j.mu.Lock()
		delete(j.inflight, cveID)
		j.mu.Unlock()
		wg.Done()
	}()

	if err := os.MkdirAll(j.cacheDir, 0o755); err != nil {
		return nil, err
	}

	url := fmt.Sprintf(redhatDetailURL, cveID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := j.client.Do(req)
	if err != nil {
		j.mu.Lock()
		j.negCache[cveID] = time.Now()
		j.mu.Unlock()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		j.mu.Lock()
		j.negCache[cveID] = time.Now()
		j.mu.Unlock()
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("redhat detail %s: http %d", cveID, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	audit.FileWritten(path, int64(len(body)))

	var d redHatDetail
	if err := json.Unmarshal(body, &d); err != nil {
		// keep the cache file even if parsing fails — surface error to caller
		return nil, fmt.Errorf("decode redhat detail %s: %w", cveID, err)
	}
	return &d, nil
}

// rhelMajor pulls the major version digit out of OS.VersionID, e.g. "9.7" → "9".
// Returns "" if the host doesn't look RHEL-shaped.
func rhelMajor(os collector.OSInfo) string {
	v := os.VersionID
	if v == "" {
		return ""
	}
	if i := strings.Index(v, "."); i > 0 {
		return v[:i]
	}
	return v
}

func normalizeFixState(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func statementSuffix(stmt string) string {
	stmt = strings.TrimSpace(stmt)
	if stmt == "" {
		return ""
	}
	if len(stmt) > 200 {
		stmt = stmt[:200] + "..."
	}
	return " - " + stmt
}

// packageNamesMatch handles the difference between Red Hat's package_state
// names (often the source name, e.g. "openssh") and the installed binary
// package name (often "openssh-server"). We accept exact match or one being
// a prefix of the other.
func packageNamesMatch(rhName, pkgName string) bool {
	if rhName == pkgName {
		return true
	}
	if strings.HasPrefix(pkgName, rhName+"-") {
		return true
	}
	if strings.HasPrefix(rhName, pkgName+"-") {
		return true
	}
	return false
}

// packageStateApplies decides whether a package_state entry names the
// installed package. Red Hat writes appstream module entries as
// "<module>:<stream>/<package>" (e.g. "php:8.0/php"); those apply only when
// the package part matches (directly or via the installed SRPM name) AND
// the installed version belongs to that stream. Without this, every
// module-delivered package (php, nodejs, postgresql, ruby, ...) got
// StatusUnknown from this judge.
func packageStateApplies(psName, pkgName string, pkgs []collector.Package) bool {
	modPart, pkgPart, isModule := strings.Cut(psName, "/")
	if !isModule {
		return packageNamesMatch(psName, pkgName)
	}
	if !packageNamesMatch(pkgPart, pkgName) && !installedSourceMatches(pkgs, pkgName, pkgPart) {
		return false
	}
	_, stream, hasStream := strings.Cut(modPart, ":")
	if !hasStream || stream == "" {
		return true
	}
	for _, p := range pkgs {
		if p.Name == pkgName && (p.Version == stream || strings.HasPrefix(p.Version, stream+".")) {
			return true
		}
	}
	return false
}
