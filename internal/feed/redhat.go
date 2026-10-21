package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const redhatAPIURL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"

type RedHatSource struct {
	client *http.Client
}

func NewRedHat() *RedHatSource {
	return &RedHatSource{
		client: &http.Client{Timeout: 10 * time.Minute},
	}
}

func (s *RedHatSource) Name() string { return "redhat" }

type rhCVE struct {
	CVE              string      `json:"CVE"`
	Severity         string      `json:"severity"`
	PublicDate       string      `json:"public_date"`
	Advisories       []string    `json:"advisories"`
	Bugzilla         string      `json:"bugzilla"`
	CVSS3Score       json.Number `json:"cvss3_score"`
	AffectedPackages []string    `json:"affected_packages"`
	ResourceURL      string      `json:"resource_url"`
	Description      string      `json:"bugzilla_description"`
}

func (s *RedHatSource) Sync(ctx context.Context, store *Store, log *slog.Logger) error {
	// Phase 1: always pull a fixed 365-day window; Phase 2 will replace this
	// with merge-based incremental sync. The current PutVulns replaces the
	// cache entirely, so an incremental fetch here would drop history.
	since := time.Now().AddDate(-1, 0, 0)
	log.Info("redhat sync starting", "since", since.Format(time.RFC3339))

	var all []Vulnerability
	page := 1
	const perPage = 1000

	for {
		params := url.Values{}
		params.Set("after", since.Format("2006-01-02"))
		params.Set("per_page", strconv.Itoa(perPage))
		params.Set("page", strconv.Itoa(page))

		req, err := http.NewRequestWithContext(ctx, "GET", redhatAPIURL+"?"+params.Encode(), nil)
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
			return fmt.Errorf("redhat http %d (page %d)", resp.StatusCode, page)
		}

		var pageData []rhCVE
		if err := json.NewDecoder(resp.Body).Decode(&pageData); err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()

		if len(pageData) == 0 {
			break
		}
		for _, c := range pageData {
			all = append(all, convertRedHat(c))
		}
		log.Debug("redhat page", "page", page, "count", len(pageData))
		if len(pageData) < perPage {
			break
		}
		page++

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}

	log.Info("redhat sync complete", "vulns", len(all))
	return store.PutVulns(s.Name(), all)
}

func (s *RedHatSource) Vulnerabilities(store *Store) ([]Vulnerability, error) {
	return store.GetVulns(s.Name())
}

func convertRedHat(c rhCVE) Vulnerability {
	v := Vulnerability{
		ID:          c.CVE,
		Source:      "redhat",
		Severity:    titleCase(c.Severity),
		Description: c.Description,
	}
	if c.CVSS3Score != "" {
		if f, err := c.CVSS3Score.Float64(); err == nil {
			v.CVSS = f
		}
	}
	if c.ResourceURL != "" {
		v.References = append(v.References, c.ResourceURL)
	}
	if c.Bugzilla != "" {
		v.References = append(v.References, c.Bugzilla)
	}
	for _, a := range c.Advisories {
		v.References = append(v.References, "https://access.redhat.com/errata/"+a)
	}
	if t, err := time.Parse(time.RFC3339, c.PublicDate); err == nil {
		v.Published = t
	}
	for _, ap := range c.AffectedPackages {
		name, fix, distro := splitRedHatNEVRA(ap)
		if name == "" {
			continue
		}
		// Appstream module errata are listed as a module NSVC
		// ("php:8.0-8100020240327101215.489197e6"), not as RPM NEVRAs. The
		// module version can't be compared with an installed RPM's NEVR,
		// so these entries are skipped here; module packages are covered
		// by OSV (Rocky/Alma publish per-RPM fixed versions) and by the
		// Red Hat applicability judge's "<module>:<stream>/<pkg>" handling.
		if strings.Contains(name, ":") {
			continue
		}
		v.Affects = append(v.Affects, AffectedPackage{
			Distro:       distro,
			Name:         name,
			FixedVersion: fix,
		})
	}
	return v
}

// Red Hat "affected_packages" entries look like "openssl-1:3.0.7-25.el9_2".
// Split returns name, "<epoch>:<version>-<release>", and inferred RHEL major
// distro tag.
var redhatNEVRARE = regexp.MustCompile(`^(.+?)-(\d+):([^-\s]+(?:-[^\s]+)?)$`)

func splitRedHatNEVRA(s string) (name, fix, distro string) {
	m := redhatNEVRARE.FindStringSubmatch(s)
	if m != nil {
		name = m[1]
		fix = m[2] + ":" + m[3]
		distro = inferRHELDistro(s)
		return
	}
	// Fallback: split on the second-to-last "-" (name-version-release).
	idx := strings.LastIndex(s, "-")
	if idx <= 0 {
		return "", "", ""
	}
	rIdx := strings.LastIndex(s[:idx], "-")
	if rIdx <= 0 {
		name = s[:idx]
		fix = s[idx+1:]
	} else {
		name = s[:rIdx]
		fix = s[rIdx+1:]
	}
	distro = inferRHELDistro(s)
	return
}

var elDistRE = regexp.MustCompile(`\.el(\d+)`)

// inferRHELDistro reads the ".elN" suffix from a Red Hat NEVRA string. Returns
// the most specific filter we can ("rhel:N"); falls back to "rhel" (matches
// any RPM-like distro) when no version tag is present.
func inferRHELDistro(s string) string {
	if m := elDistRE.FindStringSubmatch(s); m != nil {
		return "rhel:" + m[1]
	}
	return "rhel"
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}
