package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
)

// AlpineSource pulls the Alpine secdb feed for the host's running Alpine
// release. Each release/repo combination is a separate JSON file
// (main.json + community.json). The format inverts the matcher's mental
// model: it's keyed by package, listing fixed-version -> []CVE. We
// transpose into Vulnerability records keyed by CVE.
type AlpineSource struct {
	client   *http.Client
	osIDFile string
}

func NewAlpine() *AlpineSource {
	return &AlpineSource{
		client:   &http.Client{Timeout: 10 * time.Minute},
		osIDFile: "/etc/os-release",
	}
}

func (s *AlpineSource) Name() string { return "alpine" }

type alpineSecdb struct {
	DistroVersion string          `json:"distroversion"`
	RepoName      string          `json:"reponame"`
	Packages      []alpinePkgWrap `json:"packages"`
}

type alpinePkgWrap struct {
	Pkg alpinePkg `json:"pkg"`
}

type alpinePkg struct {
	Name     string              `json:"name"`
	Secfixes map[string][]string `json:"secfixes"`
}

func (s *AlpineSource) Sync(ctx context.Context, store *Store, log *slog.Logger) error {
	osi := collector.ReadOSReleaseFile(s.osIDFile)
	id, versionID := osi.ID, osi.VersionID
	if id != "alpine" {
		log.Info("alpine sync skipped (not running on alpine)")
		return store.PutVulns(s.Name(), nil)
	}
	major := versionID
	if i := strings.Index(versionID, "."); i > 0 {
		// keep "3.18" from "3.18.4"
		if j := strings.Index(versionID[i+1:], "."); j > 0 {
			major = versionID[:i+1+j]
		}
	}
	if !strings.HasPrefix(major, "v") {
		major = "v" + major
	}
	repos := []string{"main", "community"}

	log.Info("alpine sync starting", "version", major, "repos", repos)

	byCVE := map[string]*Vulnerability{}
	for _, repo := range repos {
		u := fmt.Sprintf("https://secdb.alpinelinux.org/%s/%s.json", major, repo)
		if err := s.fetchSecdb(ctx, u, major, byCVE, log); err != nil {
			log.Error("alpine repo fetch failed", "repo", repo, "err", err)
			continue
		}
	}

	vulns := make([]Vulnerability, 0, len(byCVE))
	for _, v := range byCVE {
		vulns = append(vulns, *v)
	}
	log.Info("alpine sync complete", "vulns", len(vulns))
	return store.PutVulns(s.Name(), vulns)
}

func (s *AlpineSource) Vulnerabilities(store *Store) ([]Vulnerability, error) {
	return store.GetVulns(s.Name())
}

func (s *AlpineSource) fetchSecdb(ctx context.Context, u, distroVersion string, byCVE map[string]*Vulnerability, log *slog.Logger) error {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("alpine http %d", resp.StatusCode)
	}
	var data alpineSecdb
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("decode alpine secdb: %w", err)
	}
	distro := "alpine:" + strings.TrimPrefix(distroVersion, "v")
	for _, w := range data.Packages {
		for fixedVer, cves := range w.Pkg.Secfixes {
			for _, cveID := range cves {
				cveID = strings.TrimSpace(cveID)
				if !strings.HasPrefix(cveID, "CVE-") {
					continue
				}
				v, ok := byCVE[cveID]
				if !ok {
					v = &Vulnerability{ID: cveID, Source: "alpine"}
					byCVE[cveID] = v
				}
				v.Affects = append(v.Affects, AffectedPackage{
					Distro:       distro,
					Name:         w.Pkg.Name,
					FixedVersion: fixedVer,
				})
			}
		}
	}
	return nil
}
