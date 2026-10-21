package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
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

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type osvBatchResp struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

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
// sorted by component then vulnerability ID.
func QueryOSV(ctx context.Context, client *OSVClient, comps []Component) ([]Hit, error) {
	c := client.defaults()
	var qs []Component
	for _, comp := range comps {
		if Queryable(comp) {
			qs = append(qs, comp)
		}
	}
	ids := make([][]string, len(qs)) // vuln IDs per query
	for start := 0; start < len(qs); start += c.BatchSize {
		end := start + c.BatchSize
		if end > len(qs) {
			end = len(qs)
		}
		idx := make([]int, 0, end-start)
		for i := start; i < end; i++ {
			idx = append(idx, i)
		}
		tokens := make([]string, len(idx))
		for page := 0; len(idx) > 0; page++ {
			if page >= c.MaxPages {
				return nil, fmt.Errorf("osv querybatch: more than %d pages of results", c.MaxPages)
			}
			batch := make([]osvQuery, len(idx))
			for j, i := range idx {
				batch[j].Package.Name = qs[i].Name
				batch[j].Package.Ecosystem = qs[i].Ecosystem
				batch[j].Version = qs[i].Version
				batch[j].PageToken = tokens[j]
			}
			var resp osvBatchResp
			if err := c.post(ctx, "/v1/querybatch", map[string]any{"queries": batch}, &resp); err != nil {
				return nil, err
			}
			if len(resp.Results) != len(batch) {
				return nil, fmt.Errorf("osv querybatch: %d results for %d queries", len(resp.Results), len(batch))
			}
			var nextIdx []int
			var nextTok []string
			for j, r := range resp.Results {
				for _, v := range r.Vulns {
					ids[idx[j]] = append(ids[idx[j]], v.ID)
				}
				if r.NextPageToken != "" {
					nextIdx = append(nextIdx, idx[j])
					nextTok = append(nextTok, r.NextPageToken)
				}
			}
			idx, tokens = nextIdx, nextTok
		}
	}

	// Fetch details for distinct hit IDs only.
	want := map[string]bool{}
	for _, l := range ids {
		for _, id := range l {
			want[id] = true
		}
	}
	details, err := c.fetchVulns(ctx, want)
	if err != nil {
		return nil, err
	}
	var hits []Hit
	for i, l := range ids {
		seen := map[string]bool{}
		for _, id := range l {
			if seen[id] || details[id] == nil {
				continue
			}
			seen[id] = true
			hits = append(hits, Hit{Component: qs[i], Vuln: details[id]})
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

func (c OSVClient) fetchVulns(ctx context.Context, want map[string]bool) (map[string]*OSVVuln, error) {
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make(map[string]*OSVVuln, len(ids))
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, c.Concurrency)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			var v OSVVuln
			err := c.get(ctx, "/v1/vulns/"+url.PathEscape(id), &v)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("osv vuln %s: %w", id, err)
				}
				return
			}
			out[id] = &v
		}(id)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func (c OSVClient) post(ctx context.Context, p string, body, into any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+p, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, into)
}

func (c OSVClient) get(ctx context.Context, p string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+p, nil)
	if err != nil {
		return err
	}
	return c.do(req, into)
}

func (c OSVClient) do(req *http.Request, into any) error {
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: http %d: %s", req.Method, req.URL.Path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(into)
}
