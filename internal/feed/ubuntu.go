package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const ubuntuNoticesURL = "https://ubuntu.com/security/notices.json"

// UbuntuSource pulls the Ubuntu Security Notices (USN) feed. Each notice
// carries the fix NEVRA per Ubuntu release for each affected package and
// the CVEs it addresses, which is exactly the shape Vulnerability wants.
// Per-CVE applicability ("not-affected" / "released" / "deferred" /
// "ignored") is consulted lazily by the UbuntuJudge.
type UbuntuSource struct {
	client *http.Client
}

func NewUbuntu() *UbuntuSource {
	return &UbuntuSource{client: &http.Client{Timeout: 10 * time.Minute}}
}

func (s *UbuntuSource) Name() string { return "ubuntu" }

type ubuntuNoticesPage struct {
	Notices      []ubuntuNotice `json:"notices"`
	TotalResults int            `json:"total_results"`
}

type ubuntuNotice struct {
	ID              string                        `json:"id"`
	Title           string                        `json:"title"`
	Summary         string                        `json:"summary"`
	CVES            []string                      `json:"cves"`
	ReleasePackages map[string][]ubuntuRelPackage `json:"release_packages"`
}

type ubuntuRelPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	IsSource  bool   `json:"is_source"`
	PocketURL string `json:"pocket_url"`
}

// codename -> VERSION_ID for matching against /etc/os-release.
var ubuntuCodenameToVer = map[string]string{
	"bionic":   "18.04",
	"focal":    "20.04",
	"jammy":    "22.04",
	"mantic":   "23.10",
	"noble":    "24.04",
	"oracular": "24.10",
	"plucky":   "25.04",
}

func (s *UbuntuSource) Sync(ctx context.Context, store *Store, log *slog.Logger) error {
	const perPage = 200
	const maxNotices = 5000 // ~last 2-3 years of USNs; bounded to keep sync sane

	log.Info("ubuntu sync starting", "max_notices", maxNotices)

	byCVE := map[string]*Vulnerability{}
	offset := 0
	for offset < maxNotices {
		params := url.Values{}
		params.Set("limit", strconv.Itoa(perPage))
		params.Set("offset", strconv.Itoa(offset))
		params.Set("order", "newest")

		req, err := http.NewRequestWithContext(ctx, "GET", ubuntuNoticesURL+"?"+params.Encode(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := s.client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return fmt.Errorf("ubuntu http %d", resp.StatusCode)
		}
		var page ubuntuNoticesPage
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()
		if len(page.Notices) == 0 {
			break
		}
		for _, n := range page.Notices {
			for codename, pkgs := range n.ReleasePackages {
				ver, ok := ubuntuCodenameToVer[codename]
				if !ok {
					continue
				}
				distro := "ubuntu:" + ver
				for _, p := range pkgs {
					if p.IsSource {
						continue // we want binary names for matching against dpkg-query
					}
					for _, cveID := range n.CVES {
						if !strings.HasPrefix(cveID, "CVE-") {
							continue
						}
						v, ok := byCVE[cveID]
						if !ok {
							v = &Vulnerability{
								ID:     cveID,
								Source: "ubuntu",
							}
							byCVE[cveID] = v
						}
						v.Affects = append(v.Affects, AffectedPackage{
							Distro:       distro,
							Name:         p.Name,
							FixedVersion: p.Version,
						})
						v.References = appendUnique(v.References,
							"https://ubuntu.com/security/notices/"+n.ID)
					}
				}
			}
		}
		offset += len(page.Notices)
		log.Debug("ubuntu page", "offset", offset, "total", page.TotalResults)
		if offset >= page.TotalResults {
			break
		}
	}

	vulns := make([]Vulnerability, 0, len(byCVE))
	for _, v := range byCVE {
		vulns = append(vulns, *v)
	}
	log.Info("ubuntu sync complete", "vulns", len(vulns))
	return store.PutVulns(s.Name(), vulns)
}

func (s *UbuntuSource) Vulnerabilities(store *Store) ([]Vulnerability, error) {
	return store.GetVulns(s.Name())
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
