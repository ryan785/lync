package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const nvdAPIURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type NVDSource struct {
	apiKey string
	client *http.Client
}

func NewNVD(apiKey string) *NVDSource {
	return &NVDSource{
		apiKey: apiKey,
		client: &http.Client{Timeout: 15 * time.Minute},
	}
}

func (s *NVDSource) Name() string { return "nvd" }

type nvdResp struct {
	ResultsPerPage  int           `json:"resultsPerPage"`
	StartIndex      int           `json:"startIndex"`
	TotalResults    int           `json:"totalResults"`
	Vulnerabilities []nvdVulnWrap `json:"vulnerabilities"`
}

type nvdVulnWrap struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string         `json:"id"`
	Published      string         `json:"published"`
	LastModified   string         `json:"lastModified"`
	Descriptions   []nvdDesc      `json:"descriptions"`
	Metrics        nvdMetrics     `json:"metrics"`
	Configurations []nvdConfig    `json:"configurations"`
	References     []nvdReference `json:"references"`
}

type nvdDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSV31 []nvdCVSSWrap `json:"cvssMetricV31"`
	CVSSV30 []nvdCVSSWrap `json:"cvssMetricV30"`
	CVSSV2  []nvdCVSSWrap `json:"cvssMetricV2"`
}

type nvdCVSSWrap struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

type nvdReference struct {
	URL string `json:"url"`
}

func (s *NVDSource) Sync(ctx context.Context, store *Store, log *slog.Logger) error {
	// NVD's API caps a single date range at 120 days. Without an API key
	// the rate limit is 5 requests / 30 sec, which makes the full 120-day
	// window a ~25-minute pull. Default to a tighter 30-day window when
	// unauthenticated; the user can raise it by supplying an API key.
	windowDays := 120
	if s.apiKey == "" {
		windowDays = 30
	}
	// Fix the window once: a moving lastModEndDate shifts pagination
	// between pages (records skipped or repeated, totals that keep growing).
	until := time.Now().UTC()
	since := until.AddDate(0, 0, -windowDays)
	log.Info("nvd sync starting", "since", since.Format(time.RFC3339), "window_days", windowDays, "has_api_key", s.apiKey != "")

	var all []Vulnerability
	startIdx := 0
	const perPage = 2000

	for {
		params := url.Values{}
		params.Set("lastModStartDate", since.UTC().Format("2006-01-02T15:04:05.000Z"))
		params.Set("lastModEndDate", until.Format("2006-01-02T15:04:05.000Z"))
		params.Set("startIndex", strconv.Itoa(startIdx))
		params.Set("resultsPerPage", strconv.Itoa(perPage))

		req, err := http.NewRequestWithContext(ctx, "GET", nvdAPIURL+"?"+params.Encode(), nil)
		if err != nil {
			return err
		}
		if s.apiKey != "" {
			req.Header.Set("apiKey", s.apiKey)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != 200 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return fmt.Errorf("nvd http %d", resp.StatusCode)
		}

		var r nvdResp
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()

		for _, w := range r.Vulnerabilities {
			all = append(all, convertNVD(w.CVE))
		}

		log.Debug("nvd page", "start", r.StartIndex, "count", len(r.Vulnerabilities), "total", r.TotalResults)

		startIdx += len(r.Vulnerabilities)
		if startIdx >= r.TotalResults || len(r.Vulnerabilities) == 0 {
			break
		}

		// Rate limit: 5 req / 30 sec without key, 50 with key.
		if s.apiKey == "" {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(6 * time.Second):
			}
		} else {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(600 * time.Millisecond):
			}
		}
	}

	log.Info("nvd sync complete", "vulns", len(all))
	return store.PutVulns(s.Name(), all)
}

func (s *NVDSource) Vulnerabilities(store *Store) ([]Vulnerability, error) {
	return store.GetVulns(s.Name())
}

func convertNVD(c nvdCVE) Vulnerability {
	v := Vulnerability{ID: c.ID, Source: "nvd"}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			v.Description = d.Value
			break
		}
	}
	switch {
	case len(c.Metrics.CVSSV31) > 0:
		v.CVSS = c.Metrics.CVSSV31[0].CVSSData.BaseScore
		v.Severity = c.Metrics.CVSSV31[0].CVSSData.BaseSeverity
	case len(c.Metrics.CVSSV30) > 0:
		v.CVSS = c.Metrics.CVSSV30[0].CVSSData.BaseScore
		v.Severity = c.Metrics.CVSSV30[0].CVSSData.BaseSeverity
	case len(c.Metrics.CVSSV2) > 0:
		v.CVSS = c.Metrics.CVSSV2[0].CVSSData.BaseScore
	}
	for _, ref := range c.References {
		v.References = append(v.References, ref.URL)
	}
	if t, err := time.Parse(time.RFC3339, c.Published); err == nil {
		v.Published = t
	}
	if t, err := time.Parse(time.RFC3339, c.LastModified); err == nil {
		v.Modified = t
	}
	for _, conf := range c.Configurations {
		for _, node := range conf.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				pkg := parseCPEProduct(m.Criteria)
				if pkg == "" {
					continue
				}
				v.Affects = append(v.Affects, AffectedPackage{
					Distro:       "*",
					Name:         pkg,
					VersionRange: buildVersionRange(m),
				})
			}
		}
	}
	return v
}

// CPE 2.3 format: cpe:2.3:a:vendor:product:version:update:edition:lang:...
func parseCPEProduct(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

func buildVersionRange(m nvdCPEMatch) string {
	var b strings.Builder
	switch {
	case m.VersionStartIncluding != "":
		b.WriteString(">=" + m.VersionStartIncluding)
	case m.VersionStartExcluding != "":
		b.WriteString(">" + m.VersionStartExcluding)
	}
	switch {
	case m.VersionEndIncluding != "":
		if b.Len() > 0 {
			b.WriteString(",")
		}
		b.WriteString("<=" + m.VersionEndIncluding)
	case m.VersionEndExcluding != "":
		if b.Len() > 0 {
			b.WriteString(",")
		}
		b.WriteString("<" + m.VersionEndExcluding)
	}
	return b.String()
}
