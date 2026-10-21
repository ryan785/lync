package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/feed"
)

// DefaultOSVURL is the OSV.dev API base.
const DefaultOSVURL = "https://api.osv.dev"

// OSVClient queries the OSV.dev API. The zero value uses defaults.
type OSVClient struct {
	HTTP        *http.Client // default: http.DefaultClient with a 60s timeout
	BaseURL     string       // default DefaultOSVURL
	BatchSize   int          // queries per querybatch request; default (and API max) 1000
	Concurrency int          // parallel vuln detail fetches; default 8
	MaxPages    int          // next_page_token rounds; default 20
}

// OSVVuln is the subset of an OSV record that findings need.
type OSVVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Modified string   `json:"modified"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced,omitempty"`
				Fixed        string `json:"fixed,omitempty"`
				LastAffected string `json:"last_affected,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		Versions         []string       `json:"versions"`
		DatabaseSpecific map[string]any `json:"database_specific"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

// Hit is one component OSV says is affected by one vulnerability.
type Hit struct {
	Component Component
	Vuln      *OSVVuln
}

// Queryable reports whether OSV.dev indexes the component's ecosystem and
// the component carries a usable name and version.
func Queryable(c Component) bool {
	switch c.Ecosystem {
	case EcoNPM, EcoPyPI, EcoPackagist, EcoGo, EcoCrates, EcoRubyGems, EcoNuGet:
	case EcoMaven:
		if !strings.Contains(c.Name, ":") {
			return false // artifact without a known group
		}
	default:
		return false
	}
	return c.Name != "" && c.Version != ""
}

// osvQuery is the shared querybatch entry type (kept as an alias for tests).
type osvQuery = feed.OSVQuery

func (o *OSVClient) defaults() OSVClient {
	c := OSVClient{}
	if o != nil {
		c = *o
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	if c.BaseURL == "" {
		c.BaseURL = DefaultOSVURL
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	if c.BatchSize <= 0 || c.BatchSize > 1000 {
		c.BatchSize = 1000
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 8
	}
	if c.MaxPages <= 0 {
		c.MaxPages = 20
	}
	return c
}

// QueryOSV asks OSV.dev which components are affected: querybatch for all
// queryable components (in BatchSize chunks, following next_page_token),
// then one GET /v1/vulns/{id} per distinct vulnerability that hit. Hits are
// sorted by component then vulnerability ID. The HTTP work is done by
// feed.OSVLookup, the one OSV client shared with the OS package lookups.
func QueryOSV(ctx context.Context, client *OSVClient, comps []Component) ([]Hit, error) {
	c := client.defaults()
	var qs []Component
	var queries []feed.OSVQuery
	for _, comp := range comps {
		if Queryable(comp) {
			qs = append(qs, comp)
			queries = append(queries, feed.OSVQuery{Package: feed.OSVPackage{Name: comp.Name, Ecosystem: comp.Ecosystem}, Version: comp.Version})
		}
	}
	if len(qs) == 0 {
		return nil, nil
	}
	fc := feed.NewOSVLookup("")
	fc.BaseURL = c.BaseURL
	fc.BatchSize = c.BatchSize
	fc.MaxPages = c.MaxPages
	fc.Concurrency = c.Concurrency
	if client != nil && client.HTTP != nil {
		fc.SetHTTPClient(client.HTTP)
	}
	per, err := fc.QueryBatchEach(ctx, queries)
	if err != nil {
		return nil, err
	}

	// Fetch details for distinct hit IDs only.
	want := map[string]bool{}
	var ids []string
	for _, l := range per {
		for _, h := range l {
			if !want[h.ID] {
				want[h.ID] = true
				ids = append(ids, h.ID)
			}
		}
	}
	sort.Strings(ids)
	raw, failed := fc.FetchRecords(ctx, ids)
	if len(failed) > 0 {
		return nil, fmt.Errorf("osv vuln %s: fetch failed (%d of %d)", failed[0], len(failed), len(ids))
	}
	details := make(map[string]*OSVVuln, len(raw))
	for id, data := range raw {
		var v OSVVuln
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("osv vuln %s: %w", id, err)
		}
		details[id] = &v
	}
	var hits []Hit
	for i, l := range per {
		seen := map[string]bool{}
		for _, h := range l {
			if seen[h.ID] || details[h.ID] == nil {
				continue
			}
			seen[h.ID] = true
			hits = append(hits, Hit{Component: qs[i], Vuln: details[h.ID]})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		if a.Component.Key() != b.Component.Key() {
			return a.Component.Key() < b.Component.Key()
		}
		return a.Vuln.ID < b.Vuln.ID
	})
	return hits, nil
}
