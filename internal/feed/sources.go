package feed

import (
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// Feed modes. Lookup is the default: no bulk downloads, per-package and
// per-CVE API queries at scan time. Full keeps the bulk Sync path.
const (
	ModeLookup = "lookup"
	ModeFull   = "full"
)

// ScanSources records where a scan's CVE data came from. It is written
// into every report so a reader can tell "no findings" from "the lookups
// failed": Complete is false whenever a source the scan depended on did
// not answer, and IncompleteReasons says which.
type ScanSources struct {
	Mode              string       `json:"mode"`
	CheckedAt         time.Time    `json:"checked_at"`
	Ecosystem         string       `json:"ecosystem,omitempty"`
	PackagesChecked   int          `json:"packages_checked"`
	Complete          bool         `json:"complete"`
	IncompleteReasons []string     `json:"incomplete_reasons,omitempty"`
	Sources           []SourceStat `json:"sources"`
	// UnfixedCVEs counts CVEs that affect an installed package but have
	// no fixed version published yet (not reported as findings).
	UnfixedCVEs int `json:"unfixed_cves,omitempty"`
}

// SourceStat is one data source's contribution to a scan.
type SourceStat struct {
	Name      string `json:"name"`             // osv, nvd, redhat, debian, apt, dnf, ...
	Kind      string `json:"kind"`             // lookup | bulk | local
	Status    string `json:"status"`           // ok | partial | failed | skipped
	Requests  int    `json:"requests"`         // HTTP requests (lookup) or commands (local)
	CacheHits int    `json:"cache_hits"`       // answered from the on-disk cache
	Records   int    `json:"records"`          // advisories/CVEs/updates obtained
	Bytes     int64  `json:"bytes,omitempty"`  // response bytes downloaded
	Detail    string `json:"detail,omitempty"` // human note (errors, caps)
}

// Status values for SourceStat.
const (
	StatusOK      = "ok"
	StatusPartial = "partial"
	StatusFailed  = "failed"
	StatusSkipped = "skipped"
)

// Fail marks the scan incomplete with a reason.
func (s *ScanSources) Fail(reason string) {
	s.Complete = false
	s.IncompleteReasons = append(s.IncompleteReasons, reason)
}

// FailedSources lists sources whose status is failed or partial.
func (s *ScanSources) FailedSources() []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, st := range s.Sources {
		if st.Status == StatusFailed || st.Status == StatusPartial {
			out = append(out, st.Name)
		}
	}
	return out
}

// counter wraps a RoundTripper and counts requests and response bytes.
// The base defaults to http.DefaultTransport at call time, which lyncd
// replaces with the audit transport (retry/backoff, FETCH log lines).
type counter struct {
	base     http.RoundTripper
	requests atomic.Int64
	bytes    atomic.Int64
}

func (c *counter) RoundTrip(req *http.Request) (*http.Response, error) {
	base := c.base
	if base == nil {
		base = http.DefaultTransport
	}
	c.requests.Add(1)
	resp, err := base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &countingBody{ReadCloser: resp.Body, n: &c.bytes}
	return resp, nil
}

type countingBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}
