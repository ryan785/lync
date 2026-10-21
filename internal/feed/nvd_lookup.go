package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// NVDLookup fetches single CVEs by id (GET ?cveId=) for CVEs a distro
// source already found, to enrich severity, CVSS and description. It never
// pages through date windows. Requests respect NVD's published limits (5
// per rolling 30 s without an API key, 50 with one), a per-run cap and a
// time budget; answers are cached on disk for TTL.
//
// Privacy: only CVE ids are sent.
type NVDLookup struct {
	BaseURL   string
	APIKey    string
	CacheFile string
	TTL       time.Duration // default 7 days
	Max       int           // network lookups per run (0 = 10 without key, 200 with)
	Budget    time.Duration // wall-clock budget per run (default 90s without key, 3m with)

	client *http.Client
	cnt    *counter
	now    func() time.Time
	sleep  func(context.Context, time.Duration) error
	window time.Duration
	limit  int
	stamps []time.Time
}

// NewNVDLookup returns a lookup client using http.DefaultTransport.
func NewNVDLookup(apiKey, cacheFile string) *NVDLookup {
	c := &counter{}
	return &NVDLookup{
		BaseURL:   nvdAPIURL,
		APIKey:    apiKey,
		CacheFile: cacheFile,
		client:    &http.Client{Timeout: 2 * time.Minute, Transport: c},
		cnt:       c,
	}
}

func (n *NVDLookup) defaults() {
	if n.TTL <= 0 {
		n.TTL = 7 * 24 * time.Hour
	}
	if n.Max <= 0 {
		n.Max = 10
		if n.APIKey != "" {
			n.Max = 200
		}
	}
	if n.Budget <= 0 {
		n.Budget = 90 * time.Second
		if n.APIKey != "" {
			n.Budget = 3 * time.Minute
		}
	}
	if n.window <= 0 {
		n.window = 30 * time.Second
	}
	if n.limit <= 0 {
		n.limit = 5
		if n.APIKey != "" {
			n.limit = 50
		}
	}
	if n.now == nil {
		n.now = time.Now
	}
	if n.sleep == nil {
		n.sleep = func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		}
	}
}

type nvdCacheEntry struct {
	Fetched time.Time      `json:"f"`
	Found   bool           `json:"found"`
	Vuln    *Vulnerability `json:"v,omitempty"`
}

// Lookup resolves ids in priority order (callers put the most useful
// first). Cached answers within TTL are free; the rest cost one request
// each until Max or Budget is reached, after which ids are skipped and the
// stat says so (a cap is not a failure).
func (n *NVDLookup) Lookup(ctx context.Context, ids []string) ([]Vulnerability, SourceStat) {
	n.defaults()
	startReq, startBytes := n.cnt.requests.Load(), n.cnt.bytes.Load()
	st := SourceStat{Name: "nvd", Kind: "lookup", Status: StatusOK}
	cache := map[string]*nvdCacheEntry{}
	if n.CacheFile != "" {
		if data, err := os.ReadFile(n.CacheFile); err == nil {
			_ = json.Unmarshal(data, &cache)
		}
	}
	start := n.now()
	var out []Vulnerability
	var failed []string
	fetched, capped := 0, 0
	for _, id := range ids {
		if e := cache[id]; e != nil && n.now().Sub(e.Fetched) < n.TTL {
			st.CacheHits++
			if e.Found && e.Vuln != nil {
				out = append(out, *e.Vuln)
			}
			continue
		}
		if fetched >= n.Max || n.now().Sub(start) >= n.Budget || ctx.Err() != nil {
			capped++
			continue
		}
		if err := n.wait(ctx); err != nil {
			capped++
			continue
		}
		fetched++
		v, found, err := n.fetch(ctx, id)
		if err != nil {
			failed = append(failed, id)
			continue
		}
		e := &nvdCacheEntry{Fetched: n.now(), Found: found}
		if found {
			tv := trimNVD(v)
			e.Vuln = &tv
			out = append(out, tv)
		}
		cache[id] = e
	}
	// Forget entries far past their TTL so the file stays small.
	for id, e := range cache {
		if n.now().Sub(e.Fetched) > 4*n.TTL {
			delete(cache, id)
		}
	}
	if n.CacheFile != "" {
		writeJSONFile(n.CacheFile, cache)
	}
	st.Records = len(out)
	st.Requests = int(n.cnt.requests.Load() - startReq)
	st.Bytes = n.cnt.bytes.Load() - startBytes
	var notes []string
	if capped > 0 {
		notes = append(notes, fmt.Sprintf("%d CVE(s) not looked up this run (cap %d per run, rate limit %d/30s%s); later scans continue from the cache",
			capped, n.Max, n.limit, map[bool]string{true: ", API key set", false: ", no API key"}[n.APIKey != ""]))
	}
	if len(failed) > 0 {
		st.Status = StatusPartial
		if len(out) == 0 && st.CacheHits == 0 {
			st.Status = StatusFailed
		}
		notes = append(notes, fmt.Sprintf("%d lookup(s) failed (e.g. %s)", len(failed), failed[0]))
	}
	st.Detail = strings.Join(notes, "; ")
	return out, st
}

// wait enforces the rolling-window rate limit.
func (n *NVDLookup) wait(ctx context.Context) error {
	now := n.now()
	keep := n.stamps[:0]
	for _, t := range n.stamps {
		if now.Sub(t) < n.window {
			keep = append(keep, t)
		}
	}
	n.stamps = keep
	if len(n.stamps) >= n.limit {
		d := n.window - now.Sub(n.stamps[0]) + 250*time.Millisecond
		if err := n.sleep(ctx, d); err != nil {
			return err
		}
		n.stamps = n.stamps[1:]
	}
	n.stamps = append(n.stamps, n.now())
	return nil
}

func (n *NVDLookup) fetch(ctx context.Context, id string) (Vulnerability, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", n.BaseURL+"?cveId="+url.QueryEscape(id), nil)
	if err != nil {
		return Vulnerability{}, false, err
	}
	if n.APIKey != "" {
		req.Header.Set("apiKey", n.APIKey)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return Vulnerability{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, resp.Body)
		return Vulnerability{}, false, nil
	}
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return Vulnerability{}, false, fmt.Errorf("nvd http %d", resp.StatusCode)
	}
	var r nvdResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return Vulnerability{}, false, err
	}
	for _, w := range r.Vulnerabilities {
		if w.CVE.ID == id {
			return convertNVD(w.CVE), true, nil
		}
	}
	return Vulnerability{}, false, nil
}

// trimNVD dedupes CPE entries (kernel CVEs list hundreds) and trims text.
func trimNVD(v Vulnerability) Vulnerability {
	v = trimVuln(v)
	seen := map[string]bool{}
	var aff []AffectedPackage
	for _, a := range v.Affects {
		k := a.Name + "|" + a.VersionRange
		if seen[k] || len(aff) >= 50 {
			continue
		}
		seen[k] = true
		aff = append(aff, a)
	}
	v.Affects = aff
	return v
}
