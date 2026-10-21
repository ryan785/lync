// Package lookup is the default ("lookup mode") way Lync gets CVE data:
// nothing is bulk-downloaded. One scan
//
//  1. asks OSV.dev which advisories affect each installed package
//     (POST /v1/querybatch, then GET /v1/vulns/{id} for the hits only);
//  2. on RHEL-family hosts, fetches Red Hat's per-CVE record for every CVE
//     that matched (severity, fixed NEVRAs, package_state for the judge);
//  3. asks NVD by CVE id for matched CVEs that still lack a CVSS score.
//
// The result is a []feed.Vulnerability for the ordinary matcher, so
// version comparison, module streams, distro-beats-NVD and the
// applicability judges behave exactly as in full mode.
package lookup

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ryan785/lync/internal/audit"
	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/matcher"
)

// Config selects and tunes the lookups.
type Config struct {
	CacheDir  string // <feed.cache_dir>/lookup
	TTL       time.Duration
	OSV       bool
	NVD       bool
	RedHat    bool
	NVDKey    string
	NVDMax    int
	RedHatMax int

	// Endpoint overrides (tests).
	OSVURL    string
	NVDURL    string
	RedHatURL string
}

// Client runs lookups. Safe for sequential reuse across scans.
type Client struct {
	cfg     Config
	log     *slog.Logger
	osv     *feed.OSVLookup
	nvd     *feed.NVDLookup
	Details *feed.RedHatDetails // shared with the Red Hat judge
}

// New builds a client. redhatDetailsDir is where per-CVE Red Hat records
// are cached (the judge reads the same files).
func New(cfg Config, redhatDetailsDir string, log *slog.Logger) *Client {
	c := &Client{cfg: cfg, log: log}
	c.osv = feed.NewOSVLookup(filepath.Join(cfg.CacheDir, "osv.json"))
	if cfg.OSVURL != "" {
		c.osv.BaseURL = cfg.OSVURL
	}
	c.nvd = feed.NewNVDLookup(cfg.NVDKey, filepath.Join(cfg.CacheDir, "nvd.json"))
	c.nvd.TTL = 7 * 24 * time.Hour
	if cfg.TTL > 7*24*time.Hour {
		c.nvd.TTL = cfg.TTL
	}
	c.nvd.Max = cfg.NVDMax
	if cfg.NVDURL != "" {
		c.nvd.BaseURL = cfg.NVDURL
	}
	c.Details = feed.NewRedHatDetails(redhatDetailsDir)
	if cfg.TTL > 0 {
		c.Details.TTL = cfg.TTL
	}
	if cfg.RedHatURL != "" {
		c.Details.URL = cfg.RedHatURL
	}
	if c.cfg.RedHatMax <= 0 {
		c.cfg.RedHatMax = 500
	}
	return c
}

// Names lists the lookups this client will run.
func (c *Client) Names() []string {
	var n []string
	if c.cfg.OSV {
		n = append(n, "osv")
	}
	if c.cfg.RedHat {
		n = append(n, "redhat")
	}
	if c.cfg.NVD {
		n = append(n, "nvd")
	}
	return n
}

// Result of a lookup scan.
type Result struct {
	Vulns   []feed.Vulnerability
	Sources feed.ScanSources
}

func isRHELFamily(os collector.OSInfo) bool {
	switch os.ID {
	case "rhel", "rocky", "almalinux", "centos", "ol":
		return true
	}
	for _, l := range os.IDLike {
		if l == "rhel" {
			return true
		}
	}
	return false
}

func rhelMajor(os collector.OSInfo) string {
	v := os.VersionID
	if i := strings.Index(v, "."); i > 0 {
		return v[:i]
	}
	return v
}

// Scan runs all enabled lookups for the host's packages.
func (c *Client) Scan(ctx context.Context, facts *collector.Facts) *Result {
	res := &Result{Sources: feed.ScanSources{Mode: feed.ModeLookup, CheckedAt: time.Now(), Complete: true}}
	src := &res.Sources
	if !c.cfg.OSV && !c.cfg.NVD && !c.cfg.RedHat {
		src.Fail("no vulnerability sources enabled: CVE matching was skipped")
		return res
	}
	eco, ok := feed.EcosystemForOS(facts.OS)
	if c.cfg.OSV {
		if !ok {
			src.Sources = append(src.Sources, feed.SourceStat{Name: "osv", Kind: "lookup", Status: feed.StatusSkipped,
				Detail: fmt.Sprintf("OSV.dev has no ecosystem for %s %s", facts.OS.ID, facts.OS.VersionID)})
			src.Fail(fmt.Sprintf("no OSV ecosystem for %s %s: installed packages were not checked for CVEs (use feed.mode: full with the distro feed)", facts.OS.ID, facts.OS.VersionID))
		} else {
			src.Ecosystem = eco.Name
			start := time.Now()
			r := c.osv.Scan(ctx, eco, facts.Packages)
			src.PackagesChecked = r.PackagesChecked
			src.Sources = append(src.Sources, r.Stat)
			res.Vulns = append(res.Vulns, r.Vulns...)
			audit.Log("LOOKUP", "osv ecosystem=%q packages=%d advisories=%d cache_hits=%d requests=%d bytes=%s status=%s dur=%s",
				eco.Name, r.PackagesChecked, r.Advisories, r.Stat.CacheHits, r.Stat.Requests, audit.Size(r.Stat.Bytes), r.Stat.Status, time.Since(start).Round(time.Millisecond))
			if r.Err != nil {
				src.Fail(r.Err.Error())
			}
		}
	} else if ok {
		src.Ecosystem = eco.Name
	}

	// Candidate CVEs: what the OSV data already matches on this host.
	cands := matcher.Match(facts, res.Vulns, nil)
	src.UnfixedCVEs = countUnfixed(facts, res.Vulns)
	var ids []string
	seen := map[string]bool{}
	for _, f := range cands {
		if !seen[f.CVE] {
			seen[f.CVE] = true
			ids = append(ids, f.CVE)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))

	if c.cfg.RedHat && isRHELFamily(facts.OS) {
		rh := c.redhat(ctx, ids, rhelMajor(facts.OS))
		src.Sources = append(src.Sources, rh.stat)
		res.Vulns = append(res.Vulns, rh.vulns...)
		if rh.stat.Status == feed.StatusFailed || rh.stat.Status == feed.StatusPartial {
			src.Fail("redhat: " + rh.stat.Detail)
		}
	}

	if c.cfg.NVD {
		// Only CVEs nothing else has scored: NVD is enrichment, and its
		// rate limit is the slowest part of a lookup scan.
		scored := map[string]bool{}
		for _, v := range res.Vulns {
			if v.CVSS > 0 {
				scored[v.ID] = true
			}
		}
		var need []string
		for _, id := range ids {
			if !scored[id] {
				need = append(need, id)
			}
		}
		start := time.Now()
		vs, st := c.nvd.Lookup(ctx, need)
		src.Sources = append(src.Sources, st)
		res.Vulns = append(res.Vulns, vs...)
		audit.Log("LOOKUP", "nvd candidates=%d unscored=%d found=%d cache_hits=%d requests=%d bytes=%s status=%s dur=%s %s",
			len(ids), len(need), len(vs), st.CacheHits, st.Requests, audit.Size(st.Bytes), st.Status, time.Since(start).Round(time.Millisecond), st.Detail)
		if st.Status == feed.StatusFailed || st.Status == feed.StatusPartial {
			src.Fail("nvd: " + st.Detail + " (severity enrichment incomplete)")
		}
	}
	return res
}

// countUnfixed counts CVEs whose only data for an installed package is an
// "unfixed" entry (affected, no fix published).
func countUnfixed(facts *collector.Facts, vulns []feed.Vulnerability) int {
	installed := map[string]bool{}
	for _, p := range facts.Packages {
		installed[p.Name] = true
		if s := p.SourceName(); s != "" {
			installed[s] = true
		}
	}
	ids := map[string]bool{}
	for _, v := range vulns {
		for _, a := range v.Affects {
			if a.Status == "unfixed" && installed[a.Name] && matcher.DistroMatches(a.Distro, facts.OS) {
				ids[v.ID] = true
			}
		}
	}
	return len(ids)
}

type rhResult struct {
	vulns []feed.Vulnerability
	stat  feed.SourceStat
}

func (c *Client) redhat(ctx context.Context, ids []string, major string) rhResult {
	st := feed.SourceStat{Name: "redhat", Kind: "lookup", Status: feed.StatusOK}
	r0, b0 := c.Details.Counts()
	capped := 0
	if len(ids) > c.cfg.RedHatMax {
		capped = len(ids) - c.cfg.RedHatMax
		ids = ids[:c.cfg.RedHatMax]
	}
	var mu sync.Mutex
	var out []feed.Vulnerability
	var failed []string
	jobs := make(chan string)
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				d, cached, err := c.Details.Get(ctx, id)
				mu.Lock()
				switch {
				case err != nil:
					failed = append(failed, id)
				case d != nil:
					out = append(out, feed.RedHatDetailToVuln(id, d, major))
				}
				if cached {
					st.CacheHits++
				}
				mu.Unlock()
			}
		}()
	}
	for _, id := range ids {
		jobs <- id
	}
	close(jobs)
	wg.Wait()
	r1, b1 := c.Details.Counts()
	st.Requests, st.Bytes, st.Records = r1-r0, b1-b0, len(out)
	var notes []string
	if capped > 0 {
		notes = append(notes, fmt.Sprintf("%d CVE(s) over the per-run cap of %d not looked up", capped, c.cfg.RedHatMax))
	}
	if len(failed) > 0 {
		st.Status = feed.StatusPartial
		if len(out) == 0 {
			st.Status = feed.StatusFailed
		}
		notes = append(notes, fmt.Sprintf("%d of %d lookups failed (e.g. %s)", len(failed), len(ids), failed[0]))
	}
	st.Detail = strings.Join(notes, "; ")
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	audit.Log("LOOKUP", "redhat cves=%d found=%d cache_hits=%d requests=%d bytes=%s status=%s %s",
		len(ids), len(out), st.CacheHits, st.Requests, audit.Size(st.Bytes), st.Status, st.Detail)
	return rhResult{vulns: out, stat: st}
}

// CVE gathers everything the lookup sources know about one CVE for this
// host: OSV (CVE record, the distro's per-CVE record, related distro
// advisories, cached advisories), Red Hat's per-CVE record on RHEL-family
// hosts, and NVD by id.
func (c *Client) CVE(ctx context.Context, facts *collector.Facts, id string) ([]feed.Vulnerability, feed.ScanSources) {
	src := feed.ScanSources{Mode: feed.ModeLookup, CheckedAt: time.Now(), Complete: true}
	var vulns []feed.Vulnerability
	eco, ok := feed.EcosystemForOS(facts.OS)
	if c.cfg.OSV {
		if ok {
			src.Ecosystem = eco.Name
			vs, st := c.osv.CVE(ctx, eco, id)
			vulns = append(vulns, vs...)
			src.Sources = append(src.Sources, st)
			if st.Status == feed.StatusFailed || st.Status == feed.StatusPartial {
				src.Fail("osv: " + st.Detail)
			}
		} else {
			src.Fail(fmt.Sprintf("no OSV ecosystem for %s %s", facts.OS.ID, facts.OS.VersionID))
		}
	}
	if c.cfg.RedHat && isRHELFamily(facts.OS) {
		r := c.redhat(ctx, []string{id}, rhelMajor(facts.OS))
		vulns = append(vulns, r.vulns...)
		src.Sources = append(src.Sources, r.stat)
		if r.stat.Status == feed.StatusFailed {
			src.Fail("redhat: " + r.stat.Detail)
		}
	}
	if c.cfg.NVD {
		vs, st := c.nvd.Lookup(ctx, []string{id})
		vulns = append(vulns, vs...)
		src.Sources = append(src.Sources, st)
		if st.Status == feed.StatusFailed {
			src.Fail("nvd: " + st.Detail)
		}
	}
	return vulns, src
}
