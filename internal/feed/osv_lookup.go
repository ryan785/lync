package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ryan785/lync/internal/audit"
	"github.com/ryan785/lync/internal/collector"
)

// OSVAPIURL is the public OSV.dev API.
const OSVAPIURL = "https://api.osv.dev"

// osvBatchMax is the querybatch limit per request (OSV.dev documents 1000).
const osvBatchMax = 1000

// OSVLookup queries OSV.dev per installed package instead of downloading
// an ecosystem's all.zip: one POST /v1/querybatch per 1000 packages, then
// GET /v1/vulns/{id} only for the advisories that hit, reusing cached
// details while the record's "modified" stamp is unchanged.
//
// Privacy: the request bodies contain installed package names and versions.
type OSVLookup struct {
	BaseURL     string
	CacheFile   string        // JSON cache of converted advisories ("" = no cache)
	Concurrency int           // parallel detail fetches (default 8)
	MaxAge      time.Duration // refetch a cached advisory after this even if unmodified (default 7d)
	Forget      time.Duration // drop cache entries not seen for this long (default 30d)

	client *http.Client
	cnt    *counter
	now    func() time.Time
}

// NewOSVLookup returns a client using http.DefaultTransport (the audit
// transport under lyncd: retries, backoff, FETCH lines).
func NewOSVLookup(cacheFile string) *OSVLookup {
	c := &counter{}
	return &OSVLookup{
		BaseURL:   OSVAPIURL,
		CacheFile: cacheFile,
		client:    &http.Client{Timeout: 5 * time.Minute, Transport: c},
		cnt:       c,
		now:       time.Now,
	}
}

func (o *OSVLookup) defaults() {
	if o.Concurrency <= 0 {
		o.Concurrency = 8
	}
	if o.MaxAge <= 0 {
		o.MaxAge = 7 * 24 * time.Hour
	}
	if o.Forget <= 0 {
		o.Forget = 30 * 24 * time.Hour
	}
	if o.now == nil {
		o.now = time.Now
	}
}

// OSVPackage names a package in one OSV ecosystem.
type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// OSVQuery is one entry of a POST /v1/querybatch request.
type OSVQuery struct {
	Package   OSVPackage `json:"package"`
	Version   string     `json:"version"`
	PageToken string     `json:"page_token,omitempty"`
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

type osvCacheEntry struct {
	Modified string          `json:"m,omitempty"`
	Fetched  time.Time       `json:"f"`
	Seen     time.Time       `json:"s"`
	Vulns    []Vulnerability `json:"v,omitempty"`
}

type osvCache struct {
	Version   int                       `json:"version"`
	Ecosystem string                    `json:"ecosystem"`
	Records   map[string]*osvCacheEntry `json:"records"`
}

// OSVScanResult is the outcome of one lookup scan.
type OSVScanResult struct {
	Vulns           []Vulnerability
	Stat            SourceStat
	PackagesChecked int
	Advisories      int
	Err             error // non-nil when the result is incomplete
}

// Scan looks up every installed package. A failed querybatch makes the
// result incomplete (Err set, Stat failed); failed detail fetches make it
// partial. Cached details are used when a fetch fails.
func (o *OSVLookup) Scan(ctx context.Context, eco HostEcosystem, pkgs []collector.Package) (res OSVScanResult) {
	o.defaults()
	startReq, startBytes := o.cnt.requests.Load(), o.cnt.bytes.Load()
	res = OSVScanResult{Stat: SourceStat{Name: "osv", Kind: "lookup", Status: StatusOK}}
	defer func() {
		res.Stat.Requests = int(o.cnt.requests.Load() - startReq)
		res.Stat.Bytes = o.cnt.bytes.Load() - startBytes
	}()

	type qk struct{ name, version string }
	seenQ := map[qk]bool{}
	var queries []OSVQuery
	pkgsSeen := map[string]bool{}
	for _, p := range pkgs {
		names, ver := osvQueries(p)
		if ver == "" {
			continue
		}
		pkgsSeen[p.Name] = true
		for _, n := range names {
			if n == "" || seenQ[qk{n, ver}] {
				continue
			}
			seenQ[qk{n, ver}] = true
			for _, e := range eco.Query {
				queries = append(queries, OSVQuery{Package: OSVPackage{Name: n, Ecosystem: e}, Version: ver})
			}
		}
	}
	res.PackagesChecked = len(pkgsSeen)

	hits, err := o.QueryBatch(ctx, queries)
	if err != nil {
		res.Err = fmt.Errorf("osv querybatch: %w", err)
		res.Stat.Status = StatusFailed
		res.Stat.Detail = res.Err.Error()
		return res
	}
	res.Advisories = len(hits)

	cache := o.loadCache(eco.Name)
	now := o.now()
	var need []string
	for _, id := range sortedKeys(hits) {
		e := cache.Records[id]
		if e != nil && e.Modified == hits[id] && now.Sub(e.Fetched) < o.MaxAge {
			res.Stat.CacheHits++
			e.Seen = now
			continue
		}
		need = append(need, id)
	}

	fetched, failed := o.fetchDetails(ctx, need, eco)
	for id, vs := range fetched {
		cache.Records[id] = &osvCacheEntry{Modified: hits[id], Fetched: now, Seen: now, Vulns: vs}
	}
	if len(failed) > 0 {
		res.Stat.Status = StatusPartial
		res.Stat.Detail = fmt.Sprintf("%d of %d advisory details could not be fetched (e.g. %s)", len(failed), len(need), failed[0])
		res.Err = errors.New("osv: " + res.Stat.Detail)
	}
	for _, id := range sortedKeys(hits) {
		if e := cache.Records[id]; e != nil {
			e.Seen = now
			res.Vulns = append(res.Vulns, e.Vulns...)
		}
	}
	res.Stat.Records = len(hits)
	o.saveCache(cache, now)
	return res
}

// QueryBatch runs every query against POST /v1/querybatch (chunked at
// 1000, following next_page_token) and returns the advisory ids hit, each
// with its "modified" stamp. Reusable by any caller that has its own
// package list (language ecosystems, containers): build OSVQuery values
// with the OSV ecosystem name ("npm", "PyPI", "Debian:12", ...).
func (o *OSVLookup) QueryBatch(ctx context.Context, queries []OSVQuery) (map[string]string, error) {
	hits := map[string]string{}
	pending := queries
	for round := 0; len(pending) > 0; round++ {
		if round > 50 {
			return hits, errors.New("too many result pages")
		}
		var next []OSVQuery
		for start := 0; start < len(pending); start += osvBatchMax {
			end := start + osvBatchMax
			if end > len(pending) {
				end = len(pending)
			}
			chunk := pending[start:end]
			body, err := json.Marshal(map[string]any{"queries": chunk})
			if err != nil {
				return hits, err
			}
			var r osvBatchResp
			if err := o.postJSON(ctx, o.BaseURL+"/v1/querybatch", body, &r); err != nil {
				return hits, err
			}
			if len(r.Results) != len(chunk) {
				return hits, fmt.Errorf("querybatch returned %d results for %d queries", len(r.Results), len(chunk))
			}
			for i, qr := range r.Results {
				for _, v := range qr.Vulns {
					if v.Modified > hits[v.ID] {
						hits[v.ID] = v.Modified
					} else if _, ok := hits[v.ID]; !ok {
						hits[v.ID] = v.Modified
					}
				}
				if qr.NextPageToken != "" {
					q := chunk[i]
					q.PageToken = qr.NextPageToken
					next = append(next, q)
				}
			}
		}
		pending = next
	}
	return hits, nil
}

func (o *OSVLookup) postJSON(ctx context.Context, u string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// GetRecordJSON fetches GET /v1/vulns/{id} and returns the raw advisory
// JSON (found=false on 404), for callers that convert records themselves.
func (o *OSVLookup) GetRecordJSON(ctx context.Context, id string) (raw json.RawMessage, found bool, err error) {
	o.defaults()
	var r json.RawMessage
	found, err = o.getInto(ctx, id, &r)
	return r, found, err
}

// getRecord fetches one advisory. found=false on 404.
func (o *OSVLookup) getRecord(ctx context.Context, id string) (rec *osvRecord, found bool, err error) {
	var r osvRecord
	found, err = o.getInto(ctx, id, &r)
	if err != nil || !found {
		return nil, found, err
	}
	return &r, true, nil
}

func (o *OSVLookup) getInto(ctx context.Context, id string, out any) (found bool, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", o.BaseURL+"/v1/vulns/"+url.PathEscape(id), nil)
	if err != nil {
		return false, err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, resp.Body)
		return false, nil
	}
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return false, fmt.Errorf("http %d", resp.StatusCode)
	}
	return true, json.NewDecoder(resp.Body).Decode(out)
}

// fetchDetails fetches advisories concurrently and converts them for the
// host. Returns converted vulns per id and the ids that failed.
func (o *OSVLookup) fetchDetails(ctx context.Context, ids []string, eco HostEcosystem) (map[string][]Vulnerability, []string) {
	out := map[string][]Vulnerability{}
	var failed []string
	var mu sync.Mutex
	jobs := make(chan string)
	var wg sync.WaitGroup
	for w := 0; w < o.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				rec, found, err := o.getRecord(ctx, id)
				mu.Lock()
				switch {
				case err != nil:
					failed = append(failed, id)
				case !found:
					out[id] = nil
				default:
					var vs []Vulnerability
					for _, v := range osvToVulns(rec, eco.Accept, eco.Distro, true) {
						vs = append(vs, trimVuln(v))
					}
					out[id] = vs
				}
				mu.Unlock()
			}
		}()
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		jobs <- id
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		for _, id := range ids {
			if _, ok := out[id]; !ok && !contains(failed, id) {
				failed = append(failed, id)
			}
		}
	}
	return out, failed
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// CVE answers "which distro advisories cover this CVE on this host": the
// CVE record itself, the distro's per-CVE record (DEBIAN-CVE-X, ...),
// related advisories with the distro's prefix (RLSA-, ALSA-, ...), and any
// cached advisory from earlier scans that names the CVE.
func (o *OSVLookup) CVE(ctx context.Context, eco HostEcosystem, cveID string) ([]Vulnerability, SourceStat) {
	o.defaults()
	startReq, startBytes := o.cnt.requests.Load(), o.cnt.bytes.Load()
	st := SourceStat{Name: "osv", Kind: "lookup", Status: StatusOK}
	ids := []string{cveID}
	for _, t := range eco.PerCVE {
		ids = append(ids, fmt.Sprintf(t, cveID))
	}
	var vulns []Vulnerability
	var errs []string
	seen := map[string]bool{}
	for i := 0; i < len(ids); i++ {
		id := ids[i]
		if seen[id] {
			continue
		}
		seen[id] = true
		rec, found, err := o.getRecord(ctx, id)
		if err != nil {
			errs = append(errs, id+": "+err.Error())
			continue
		}
		if !found {
			continue
		}
		st.Records++
		for _, rel := range append(append([]string{}, rec.Related...), rec.Aliases...) {
			for _, p := range eco.AdvisoryPrefixes {
				if strings.HasPrefix(rel, p) {
					ids = append(ids, rel)
				}
			}
		}
		for _, v := range osvToVulns(rec, eco.Accept, eco.Distro, true) {
			if v.ID == cveID {
				vulns = append(vulns, v)
			}
		}
	}
	// Advisories cached by earlier scans (Rocky RLSA ids are not linked
	// from the CVE record).
	cache := o.loadCache(eco.Name)
	for _, id := range sortedKeys(cache.Records) {
		if seen[id] {
			continue
		}
		for _, v := range cache.Records[id].Vulns {
			if v.ID == cveID {
				vulns = append(vulns, v)
				st.CacheHits++
			}
		}
	}
	st.Requests = int(o.cnt.requests.Load() - startReq)
	st.Bytes = o.cnt.bytes.Load() - startBytes
	if len(errs) > 0 {
		st.Status = StatusFailed
		if st.Records > 0 {
			st.Status = StatusPartial
		}
		st.Detail = strings.Join(errs, "; ")
	}
	return vulns, st
}

func (o *OSVLookup) loadCache(ecosystem string) *osvCache {
	c := &osvCache{Version: 1, Ecosystem: ecosystem, Records: map[string]*osvCacheEntry{}}
	if o.CacheFile == "" {
		return c
	}
	data, err := os.ReadFile(o.CacheFile)
	if err != nil {
		return c
	}
	var disk osvCache
	if json.Unmarshal(data, &disk) != nil || disk.Version != 1 || disk.Ecosystem != ecosystem || disk.Records == nil {
		return c
	}
	return &disk
}

func (o *OSVLookup) saveCache(c *osvCache, now time.Time) {
	if o.CacheFile == "" {
		return
	}
	for id, e := range c.Records {
		if now.Sub(e.Seen) > o.Forget {
			delete(c.Records, id)
		}
	}
	writeJSONFile(o.CacheFile, c)
}

// writeJSONFile writes v atomically (tmp + rename), mode 0600.
func writeJSONFile(path string, v any) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return
	}
	audit.FileWritten(path, int64(len(data)))
}
