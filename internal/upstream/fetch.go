package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ryan785/lync/internal/audit"
)

// maxBody caps one downloaded data file (Node's index.json is ~350 KB).
const maxBody = 32 << 20

// Fetcher downloads small upstream data files into a cache directory and
// revalidates them with If-None-Match / If-Modified-Since, so a scan
// usually costs one 304 per file. A copy younger than MaxAge is used
// without any request.
type Fetcher struct {
	Dir    string
	MaxAge time.Duration // default 1h
	Client *http.Client  // default: http.DefaultTransport (the audit transport under lyncd)

	Requests  int
	CacheHits int
	Bytes     int64

	now func() time.Time
}

type cacheMeta struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Fetched      time.Time `json:"fetched"`
}

// fetchResult is one file: its body and whether it is a stale copy kept
// because the refresh failed (Err set).
type fetchResult struct {
	Data    []byte
	Fetched time.Time
	Stale   bool
	Err     error
}

func (f *Fetcher) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

// Get returns the file named name (cached as <Dir>/<name>) from url.
func (f *Fetcher) Get(ctx context.Context, name, url string) fetchResult {
	maxAge := f.MaxAge
	if maxAge <= 0 {
		maxAge = time.Hour
	}
	dataPath := filepath.Join(f.Dir, name)
	metaPath := dataPath + ".meta"
	var meta cacheMeta
	cached, cerr := os.ReadFile(dataPath)
	if cerr == nil {
		if b, err := os.ReadFile(metaPath); err == nil {
			_ = json.Unmarshal(b, &meta)
		}
		if meta.URL != url {
			meta = cacheMeta{} // endpoint changed: don't revalidate against it
		} else if f.clock().Sub(meta.Fetched) < maxAge {
			f.CacheHits++
			return fetchResult{Data: cached, Fetched: meta.Fetched}
		}
	}
	data, newMeta, notModified, err := f.request(ctx, url, meta, cerr == nil)
	switch {
	case err != nil && cerr == nil:
		return fetchResult{Data: cached, Fetched: meta.Fetched, Stale: true, Err: err}
	case err != nil:
		return fetchResult{Err: err}
	case notModified:
		f.CacheHits++
		meta.Fetched = f.clock()
		writeFile(metaPath, mustJSON(meta))
		return fetchResult{Data: cached, Fetched: meta.Fetched}
	}
	writeFile(dataPath, data)
	writeFile(metaPath, mustJSON(newMeta))
	return fetchResult{Data: data, Fetched: newMeta.Fetched}
}

func (f *Fetcher) request(ctx context.Context, url string, meta cacheMeta, haveCache bool) ([]byte, cacheMeta, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, meta, false, err
	}
	if haveCache {
		if meta.ETag != "" {
			req.Header.Set("If-None-Match", meta.ETag)
		}
		if meta.LastModified != "" {
			req.Header.Set("If-Modified-Since", meta.LastModified)
		}
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	f.Requests++
	resp, err := client.Do(req)
	if err != nil {
		return nil, meta, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && haveCache {
		io.Copy(io.Discard, resp.Body)
		return nil, meta, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, meta, false, fmt.Errorf("%s: http %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	f.Bytes += int64(len(data))
	if err != nil {
		return nil, meta, false, err
	}
	if len(data) > maxBody {
		return nil, meta, false, errors.New(url + ": response too large")
	}
	return data, cacheMeta{
		URL:          url,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		Fetched:      f.clock(),
	}, false, nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// writeFile replaces path atomically; errors leave the old copy (the
// next scan simply downloads again).
func writeFile(path string, data []byte) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
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
