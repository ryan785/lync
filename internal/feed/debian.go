package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const debianTrackerURL = "https://security-tracker.debian.org/tracker/data/json"

// DebianSource pulls the Debian Security Tracker bulk JSON. The file is one
// big "package -> CVE -> release -> status" tree; we flatten it into
// Vulnerability records, one AffectedPackage per CVE per release.
type DebianSource struct {
	client *http.Client
}

func NewDebian() *DebianSource {
	return &DebianSource{client: &http.Client{Timeout: 10 * time.Minute}}
}

func (s *DebianSource) Name() string { return "debian" }

type debianTrackerData map[string]map[string]debianCVE

type debianCVE struct {
	Scope       string                   `json:"scope"`
	Description string                   `json:"description"`
	DebianBug   int                      `json:"debianbug"`
	Releases    map[string]debianRelease `json:"releases"`
}

type debianRelease struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
}

// codename -> major version for VersionID matching.
var debianCodenameToMajor = map[string]string{
	"buster":   "10",
	"bullseye": "11",
	"bookworm": "12",
	"trixie":   "13",
	"forky":    "14",
}

func (s *DebianSource) Sync(ctx context.Context, store *Store, log *slog.Logger) error {
	log.Info("debian sync starting", "url", debianTrackerURL)

	req, err := http.NewRequestWithContext(ctx, "GET", debianTrackerURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("debian http %d", resp.StatusCode)
	}

	var data debianTrackerData
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("decode debian tracker: %w", err)
	}

	vulns := convertDebian(data)
	log.Info("debian sync complete", "packages", len(data), "vulns", len(vulns))
	return store.PutVulns(s.Name(), vulns)
}

func (s *DebianSource) Vulnerabilities(store *Store) ([]Vulnerability, error) {
	return store.GetVulns(s.Name())
}

func convertDebian(data debianTrackerData) []Vulnerability {
	// Group by CVE so we get one Vulnerability per CVE (not one per package),
	// with affects[] listing each (package, release) combo.
	byCVE := map[string]*Vulnerability{}
	for pkgName, cves := range data {
		for cveID, info := range cves {
			if !strings.HasPrefix(cveID, "CVE-") {
				continue
			}
			v, ok := byCVE[cveID]
			if !ok {
				v = &Vulnerability{
					ID:          cveID,
					Source:      "debian",
					Description: info.Description,
				}
				byCVE[cveID] = v
			}
			for codename, rel := range info.Releases {
				major, hasMajor := debianCodenameToMajor[codename]
				if !hasMajor {
					continue
				}
				ap := AffectedPackage{
					Distro: "debian:" + major,
					Name:   pkgName,
					Status: rel.Status,
				}
				if rel.Status == "resolved" {
					ap.FixedVersion = rel.FixedVersion
				}
				v.Affects = append(v.Affects, ap)
				if sev := mapDebianUrgency(rel.Urgency); sev != "" && v.Severity == "" {
					v.Severity = sev
				}
			}
		}
	}
	out := make([]Vulnerability, 0, len(byCVE))
	for _, v := range byCVE {
		out = append(out, *v)
	}
	return out
}

// mapDebianUrgency normalizes Debian's urgency field to Lync's severity
// vocabulary. "not yet assigned", "unimportant", and "end-of-life" intentionally
// return "" so the CVSS-based fallback in the matcher can fill in.
func mapDebianUrgency(urgency string) string {
	switch strings.ToLower(strings.TrimSpace(urgency)) {
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	}
	return ""
}
