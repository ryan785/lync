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
	"sync"
	"time"

	"github.com/ryan785/lync/internal/collector"
)

const ubuntuDetailURL = "https://ubuntu.com/security/cves/%s.json"

// UbuntuJudge consults Ubuntu's per-CVE detail endpoint and inspects
// packages[].statuses[] for the host's release codename. Caches detail
// responses on disk to keep subsequent scans cheap.
type UbuntuJudge struct {
	cacheDir string
	client   *http.Client

	mu       sync.Mutex
	inflight map[string]*sync.WaitGroup
	negCache map[string]time.Time
}

func NewUbuntuJudge(cacheDir string) *UbuntuJudge {
	return &UbuntuJudge{
		cacheDir: cacheDir,
		client:   &http.Client{Timeout: 30 * time.Second},
		inflight: map[string]*sync.WaitGroup{},
		negCache: map[string]time.Time{},
	}
}

func (j *UbuntuJudge) Name() string { return "ubuntu" }

func (j *UbuntuJudge) AppliesTo(os collector.OSInfo) bool {
	return os.ID == "ubuntu"
}

type ubuntuDetail struct {
	ID       string                `json:"id"`
	Priority string                `json:"priority"`
	Status   string                `json:"status"`
	Packages []ubuntuDetailPackage `json:"packages"`
}

type ubuntuDetailPackage struct {
	Name     string                  `json:"name"`
	Statuses []ubuntuDetailRelStatus `json:"statuses"`
}

type ubuntuDetailRelStatus struct {
	ReleaseCodename string `json:"release_codename"`
	Status          string `json:"status"`
	Description     string `json:"description"`
}

// versionIDToCodename inverse of ubuntuCodenameToVer in feed/ubuntu.go.
// Kept local to applicability so this package doesn't import feed.
var versionIDToCodename = map[string]string{
	"18.04": "bionic",
	"20.04": "focal",
	"22.04": "jammy",
	"23.10": "mantic",
	"24.04": "noble",
	"24.10": "oracular",
	"25.04": "plucky",
}

func (j *UbuntuJudge) Evaluate(ctx context.Context, cveID, pkgName string, facts *collector.Facts) (Verdict, error) {
	if cveID == "" || pkgName == "" {
		return Verdict{Status: StatusUnknown, Judge: j.Name()}, nil
	}
	codename := versionIDToCodename[facts.OS.VersionID]
	if codename == "" {
		return Verdict{Status: StatusUnknown, Judge: j.Name()}, nil
	}
	d, err := j.detail(ctx, cveID)
	if err != nil || d == nil {
		return Verdict{Status: StatusUnknown, Judge: j.Name()}, err
	}
	for _, p := range d.Packages {
		if !packageNamesMatch(p.Name, pkgName) {
			continue
		}
		for _, rs := range p.Statuses {
			if rs.ReleaseCodename != codename {
				continue
			}
			switch rs.Status {
			case "not-affected", "DNE":
				return Verdict{
					Status: StatusNotAffected, Judge: j.Name(),
					Reason: fmt.Sprintf("Ubuntu: %s for %s on %s", rs.Status, p.Name, codename),
				}, nil
			case "deferred", "ignored":
				return Verdict{
					Status: StatusDeferredOrWontFix, Judge: j.Name(),
					Reason: fmt.Sprintf("Ubuntu: %s for %s on %s", rs.Status, p.Name, codename),
				}, nil
			case "released", "needed", "pending", "active":
				return Verdict{
					Status: StatusAffected, Judge: j.Name(),
					Reason: fmt.Sprintf("Ubuntu: %s for %s on %s", rs.Status, p.Name, codename),
				}, nil
			}
		}
	}
	return Verdict{Status: StatusUnknown, Judge: j.Name()}, nil
}

func (j *UbuntuJudge) detail(ctx context.Context, cveID string) (*ubuntuDetail, error) {
	path := filepath.Join(j.cacheDir, cveID+".json")
	if data, err := os.ReadFile(path); err == nil {
		var d ubuntuDetail
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
		if data, err := os.ReadFile(path); err == nil {
			var d ubuntuDetail
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

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf(ubuntuDetailURL, cveID), nil)
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
		return nil, fmt.Errorf("ubuntu detail %s: http %d", cveID, resp.StatusCode)
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
	var d ubuntuDetail
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("decode ubuntu detail %s: %w", cveID, err)
	}
	return &d, nil
}
