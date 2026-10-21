package feed

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
)

// OSVSource pulls one bulk all.zip per ecosystem from OSV.dev. The ecosystem
// is derived from the host /etc/os-release at sync time — pulling every
// ecosystem unconditionally would waste bandwidth on data the matcher will
// never use. Detection happens inside the source; no extra API needed.
type OSVSource struct {
	client   *http.Client
	osIDFile string // override for tests
}

func NewOSV() *OSVSource {
	return &OSVSource{
		client:   &http.Client{Timeout: 10 * time.Minute},
		osIDFile: "/etc/os-release",
	}
}

func (s *OSVSource) Name() string { return "osv" }

type osvRecord struct {
	ID         string         `json:"id"`
	Aliases    []string       `json:"aliases"`
	Upstream   []string       `json:"upstream"`
	Related    []string       `json:"related"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Affected   []osvAffected  `json:"affected"`
	Severity   []osvSeverity  `json:"severity"`
	References []osvReference `json:"references"`
	Published  string         `json:"published"`
	Modified   string         `json:"modified"`
}

type osvAffected struct {
	Package           osvPackage      `json:"package"`
	Ranges            []osvRange      `json:"ranges"`
	EcosystemSpecific json.RawMessage `json:"ecosystem_specific,omitempty"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func (s *OSVSource) Sync(ctx context.Context, store *Store, log *slog.Logger) error {
	host, ok := EcosystemForOS(collector.ReadOSReleaseFile(s.osIDFile))
	if !ok {
		log.Info("osv sync skipped (no matching ecosystem for host)")
		return store.PutVulns(s.Name(), nil)
	}
	ecosystems := []string{host.Bulk}
	log.Info("osv sync starting", "ecosystems", ecosystems)

	var all []Vulnerability
	var firstErr error
	for _, eco := range ecosystems {
		v, err := s.fetchEcosystem(ctx, eco, host, log)
		if err != nil {
			log.Error("osv ecosystem fetch failed", "ecosystem", eco, "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("osv %s: %w", eco, err)
			}
			continue
		}
		all = append(all, v...)
	}
	// Don't overwrite a good cache (and stamp it fresh) with nothing when
	// the download failed: report the failure instead.
	if firstErr != nil {
		return firstErr
	}
	log.Info("osv sync complete", "vulns", len(all))
	return store.PutVulns(s.Name(), all)
}

func (s *OSVSource) Vulnerabilities(store *Store) ([]Vulnerability, error) {
	return store.GetVulns(s.Name())
}

func (s *OSVSource) fetchEcosystem(ctx context.Context, ecosystem string, host HostEcosystem, log *slog.Logger) ([]Vulnerability, error) {
	u := "https://osv-vulnerabilities.storage.googleapis.com/" + url.PathEscape(ecosystem) + "/all.zip"
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// Ecosystem not published — common for less-tracked distros.
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("osv http %d for %s", resp.StatusCode, ecosystem)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("unzip osv %s: %w", ecosystem, err)
	}
	log.Debug("osv ecosystem", "ecosystem", ecosystem, "entries", len(zr.File), "bytes", len(body))

	var vulns []Vulnerability
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var rec osvRecord
		err = json.NewDecoder(rc).Decode(&rec)
		rc.Close()
		if err != nil {
			continue
		}
		for _, v := range osvToVulns(&rec, host.Accept, host.Distro, false) {
			vulns = append(vulns, trimVuln(v))
		}
	}
	return vulns, nil
}

// convertOSV converts a record from one ecosystem's bulk export and
// returns the first CVE it covers (kept for tests; Sync uses osvToVulns,
// which emits one Vulnerability per CVE).
func convertOSV(r *osvRecord, ecosystem string) (Vulnerability, bool) {
	vs := osvToVulns(r, nil, osvEcosystemToDistroFilter(ecosystem), false)
	if len(vs) == 0 {
		return Vulnerability{}, false
	}
	return vs[0], true
}

func lastFixedInRanges(ranges []osvRange) string {
	for _, r := range ranges {
		for i := len(r.Events) - 1; i >= 0; i-- {
			if r.Events[i].Fixed != "" {
				return r.Events[i].Fixed
			}
		}
	}
	return ""
}

// osvEcosystemToDistroFilter maps OSV ecosystem strings ("Rocky Linux:9",
// "Debian:12") to our matcher's distro filter format ("rhel:9", "debian:12").
func osvEcosystemToDistroFilter(ecosystem string) string {
	parts := strings.SplitN(strings.TrimSuffix(ecosystem, ":LTS"), ":", 2)
	name := parts[0]
	ver := ""
	if len(parts) > 1 {
		ver = parts[1]
	}
	var family string
	switch name {
	case "Rocky Linux", "AlmaLinux", "Red Hat", "Red Hat Enterprise Linux", "CentOS":
		family = "rhel"
	case "Debian":
		family = "debian"
	case "Ubuntu":
		family = "ubuntu"
	case "Alpine":
		family = "alpine"
		ver = strings.TrimPrefix(ver, "v")
	case "SUSE", "openSUSE":
		family = "suse"
	default:
		family = strings.ToLower(name)
	}
	if ver == "" {
		return family
	}
	return family + ":" + ver
}

// osvEcosystemsForHost reads an os-release file and returns the OSV bulk
// export names that apply (one per host).
func osvEcosystemsForHost(osReleasePath string) []string {
	eco, ok := EcosystemForOS(collector.ReadOSReleaseFile(osReleasePath))
	if !ok {
		return nil
	}
	return []string{eco.Bulk}
}
