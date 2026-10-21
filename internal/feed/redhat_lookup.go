package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ryan785/lync/internal/audit"
)

// RedHatDetailURL is Red Hat's per-CVE Security Data API endpoint.
const RedHatDetailURL = "https://access.redhat.com/hydra/rest/securitydata/cve/%s.json"

// RedHatDetail is the subset of Red Hat's per-CVE JSON that Lync uses.
// The on-disk cache stores exactly this (trimmed) shape.
type RedHatDetail struct {
	Name            string                  `json:"name"`
	ThreatSeverity  string                  `json:"threat_severity,omitempty"`
	PublicDate      string                  `json:"public_date,omitempty"`
	Statement       string                  `json:"statement,omitempty"`
	Bugzilla        RedHatBugzilla          `json:"bugzilla,omitempty"`
	CVSS3           RedHatCVSS3             `json:"cvss3,omitempty"`
	PackageState    []RedHatPackageState    `json:"package_state,omitempty"`
	AffectedRelease []RedHatAffectedRelease `json:"affected_release,omitempty"`
}

type RedHatBugzilla struct {
	Description string `json:"description,omitempty"`
}

type RedHatCVSS3 struct {
	BaseScore string `json:"cvss3_base_score,omitempty"`
}

type RedHatPackageState struct {
	ProductName string `json:"product_name"`
	PackageName string `json:"package_name"`
	FixState    string `json:"fix_state"`
	CPE         string `json:"cpe,omitempty"`
}

type RedHatAffectedRelease struct {
	ProductName string `json:"product_name"`
	Package     string `json:"package"`
	Advisory    string `json:"advisory"`
	CPE         string `json:"cpe,omitempty"`
}

// RedHatDetails fetches and caches per-CVE details. It is shared by the
// lookup path (severity, fixed NEVRAs) and the Red Hat applicability judge
// (package_state), so each CVE is fetched at most once per TTL.
type RedHatDetails struct {
	URL      string // fmt pattern with one %s for the CVE id
	CacheDir string
	TTL      time.Duration // refetch after this (default 24h); stale data is used if a refetch fails

	client   *http.Client
	cnt      *counter
	mu       sync.Mutex
	inflight map[string]*sync.WaitGroup
	negCache map[string]time.Time
}

// NewRedHatDetails returns a client caching under cacheDir.
func NewRedHatDetails(cacheDir string) *RedHatDetails {
	c := &counter{}
	return &RedHatDetails{
		URL:      RedHatDetailURL,
		CacheDir: cacheDir,
		TTL:      24 * time.Hour,
		client:   &http.Client{Timeout: 60 * time.Second, Transport: c},
		cnt:      c,
		inflight: map[string]*sync.WaitGroup{},
		negCache: map[string]time.Time{},
	}
}

// Counts returns requests made and bytes downloaded so far.
func (r *RedHatDetails) Counts() (int, int64) {
	return int(r.cnt.requests.Load()), r.cnt.bytes.Load()
}

// ErrNotFound: Red Hat has no record of the CVE.
var ErrNotFound = errors.New("not found")

func (r *RedHatDetails) readCache(path string) (*RedHatDetail, time.Time, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, false
	}
	var d RedHatDetail
	if json.Unmarshal(data, &d) != nil {
		return nil, time.Time{}, false
	}
	return &d, fi.ModTime(), true
}

// Get returns the detail for cveID (nil, nil when Red Hat has none).
// cached reports whether the answer came from the disk cache.
func (r *RedHatDetails) Get(ctx context.Context, cveID string) (d *RedHatDetail, cached bool, err error) {
	path := filepath.Join(r.CacheDir, cveID+".json")
	stale, mtime, ok := r.readCache(path)
	if ok && (r.TTL <= 0 || time.Since(mtime) < r.TTL) {
		return stale, true, nil
	}
	r.mu.Lock()
	if t, neg := r.negCache[cveID]; neg && time.Since(t) < 10*time.Minute {
		r.mu.Unlock()
		return stale, stale != nil, nil
	}
	if wg, busy := r.inflight[cveID]; busy {
		r.mu.Unlock()
		wg.Wait()
		if d, _, ok := r.readCache(path); ok {
			return d, true, nil
		}
		return stale, stale != nil, nil
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	r.inflight[cveID] = wg
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.inflight, cveID)
		r.mu.Unlock()
		wg.Done()
	}()

	d, err = r.fetch(ctx, cveID)
	if err != nil {
		r.mu.Lock()
		r.negCache[cveID] = time.Now()
		r.mu.Unlock()
		if errors.Is(err, ErrNotFound) {
			return nil, false, nil
		}
		if stale != nil {
			return stale, true, nil // network trouble: last known answer
		}
		return nil, false, err
	}
	if err := os.MkdirAll(r.CacheDir, 0o755); err == nil {
		data, _ := json.Marshal(d)
		tmp := path + ".tmp"
		if os.WriteFile(tmp, data, 0o644) == nil && os.Rename(tmp, path) == nil {
			audit.FileWritten(path, int64(len(data)))
		}
	}
	return d, false, nil
}

func (r *RedHatDetails) fetch(ctx context.Context, cveID string) (*RedHatDetail, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf(r.URL, cveID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, resp.Body)
		return nil, ErrNotFound
	}
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("redhat detail %s: http %d", cveID, resp.StatusCode)
	}
	var d RedHatDetail
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("decode redhat detail %s: %w", cveID, err)
	}
	// Keep RHEL entries only: kernel CVEs list hundreds of products.
	ar := d.AffectedRelease[:0]
	for _, a := range d.AffectedRelease {
		if strings.HasPrefix(a.ProductName, "Red Hat Enterprise Linux") {
			ar = append(ar, a)
		}
	}
	d.AffectedRelease = ar
	ps := d.PackageState[:0]
	for _, p := range d.PackageState {
		if strings.HasPrefix(p.ProductName, "Red Hat Enterprise Linux") {
			ps = append(ps, p)
		}
	}
	d.PackageState = ps
	if len(d.Statement) > 1000 {
		d.Statement = d.Statement[:1000] + "..."
	}
	if len(d.Bugzilla.Description) > 600 {
		d.Bugzilla.Description = d.Bugzilla.Description[:600] + "..."
	}
	return &d, nil
}

// RedHatDetailToVuln converts a detail into a "redhat" Vulnerability for
// RHEL major: severity, CVSS and one fixed NEVR per package shipped for
// "Red Hat Enterprise Linux <major>" (main stream only; EUS/AUS products
// carry older z-stream builds and are skipped, module NSVCs too).
func RedHatDetailToVuln(id string, d *RedHatDetail, major string) Vulnerability {
	v := Vulnerability{
		ID:          id,
		Source:      "redhat",
		Severity:    titleCase(d.ThreatSeverity),
		Description: d.Bugzilla.Description,
		References:  []string{"https://access.redhat.com/security/cve/" + id},
	}
	if f, err := strconv.ParseFloat(d.CVSS3.BaseScore, 64); err == nil {
		v.CVSS = f
	}
	if t, err := time.Parse(time.RFC3339, d.PublicDate); err == nil {
		v.Published = t
	}
	seen := map[string]bool{}
	for _, ar := range d.AffectedRelease {
		if !rhelMainCPE(ar.CPE, major) && ar.ProductName != "Red Hat Enterprise Linux "+major {
			continue
		}
		name, fix, _ := splitRedHatNEVRA(ar.Package)
		if name == "" || strings.Contains(name, ":") || seen[name] {
			continue
		}
		seen[name] = true
		v.Affects = append(v.Affects, AffectedPackage{Distro: "rhel:" + major, Name: name, FixedVersion: fix})
		if ar.Advisory != "" {
			v.References = append(v.References, "https://access.redhat.com/errata/"+ar.Advisory)
		}
	}
	return trimVuln(v)
}

// rhelMainCPE: "cpe:/o:redhat:enterprise_linux:9" or
// "cpe:/a:redhat:enterprise_linux:9::appstream" (not rhel_eus, not 9.2).
func rhelMainCPE(cpe, major string) bool {
	parts := strings.Split(cpe, ":")
	return len(parts) >= 5 && parts[2] == "redhat" && parts[3] == "enterprise_linux" && parts[4] == major
}
