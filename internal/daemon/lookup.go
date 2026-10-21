package daemon

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/ryan785/lync/internal/audit"
	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/config"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/lookup"
)

// buildLookup maps feed.sources onto lookups: osv -> OSV.dev query API,
// nvd -> NVD by CVE id, redhat -> Red Hat per-CVE API. The distro bulk
// feeds (debian, ubuntu, alpine) are served by OSV in lookup mode, which
// carries the DSA/DLA, USN and Alpine secdb data.
func buildLookup(cfg *config.Config, log *slog.Logger) *lookup.Client {
	lc := lookup.Config{
		CacheDir:  filepath.Join(cfg.Feed.CacheDir, "lookup"),
		TTL:       cfg.Feed.Lookup.CacheTTL,
		NVDMax:    cfg.Feed.Lookup.NVDMaxPerRun,
		RedHatMax: cfg.Feed.Lookup.RedHatMaxPerRun,
	}
	for _, s := range cfg.Feed.Sources {
		if !s.Enabled {
			continue
		}
		switch s.Name {
		case "osv", "debian", "ubuntu", "alpine":
			lc.OSV = true
		case "nvd":
			lc.NVD = true
			lc.NVDKey = s.APIKey
		case "redhat":
			lc.RedHat = true
		}
	}
	return lookup.New(lc, filepath.Join(cfg.Feed.CacheDir, "redhat", "details"), log)
}

// gatherVulns returns the vulnerability data for one scan and a record of
// where it came from: lookups in lookup mode, cached bulk feeds in full
// mode.
func (d *Daemon) gatherVulns(ctx context.Context, facts *collector.Facts) ([]feed.Vulnerability, *feed.ScanSources) {
	if d.lookup != nil {
		start := time.Now()
		r := d.lookup.Scan(ctx, facts)
		src := r.Sources
		audit.Log("LOOKUP", "done vulns=%d complete=%v dur=%s cache=%s", len(r.Vulns), src.Complete, time.Since(start).Round(time.Millisecond), audit.Size(dirSize(filepath.Join(d.cfg.Feed.CacheDir))))
		return r.Vulns, &src
	}
	src := &feed.ScanSources{Mode: feed.ModeFull, CheckedAt: time.Now(), Complete: true, PackagesChecked: len(facts.Packages)}
	if eco, ok := feed.EcosystemForOS(facts.OS); ok {
		src.Ecosystem = eco.Name
	}
	d.mu.Lock()
	failed := map[string]bool{}
	for _, f := range d.failedSources {
		failed[f] = true
	}
	d.mu.Unlock()
	var all []feed.Vulnerability
	for _, s := range d.sources {
		st := feed.SourceStat{Name: s.Name(), Kind: "bulk", Status: feed.StatusOK}
		v, err := s.Vulnerabilities(d.store)
		if err != nil {
			d.log.Error("feed read failed", "source", s.Name(), "err", err)
			audit.Log("FEED", "%s read failed: %v", s.Name(), err)
			st.Status, st.Detail = feed.StatusFailed, err.Error()
			src.Fail(s.Name() + ": cache unreadable")
		} else {
			audit.Log("FEED", "%s loaded vulns=%d", s.Name(), len(v))
			all = append(all, v...)
			st.Records = len(v)
			if m, _ := d.store.GetManifest(s.Name()); m != nil {
				st.Detail = "last sync " + m.LastSync.UTC().Format(time.RFC3339)
			} else {
				st.Status, st.Detail = feed.StatusFailed, "never synced"
				src.Fail(s.Name() + ": never synced")
			}
		}
		if failed[s.Name()] && st.Status == feed.StatusOK {
			st.Status = feed.StatusPartial
			st.Detail += " (latest sync failed; using older cache)"
			src.Fail(s.Name() + ": latest sync failed")
		}
		src.Sources = append(src.Sources, st)
	}
	if len(d.sources) == 0 {
		src.Fail("no vulnerability sources enabled: CVE matching was skipped")
	}
	return all, src
}

// localCrossCheck runs the package-manager cross-check and records it.
func (d *Daemon) localCrossCheck(ctx context.Context, facts *collector.Facts, findings []finding.Finding, src *feed.ScanSources) []finding.Finding {
	manager := ""
	if len(facts.Packages) > 0 {
		manager = facts.Packages[0].Manager
	}
	ups, st := lookup.LocalCheck(ctx, nil, manager, d.cfg.Feed.LocalRefresh)
	if st.Status == feed.StatusOK {
		var summary string
		findings, summary = lookup.CrossCheck(facts, findings, ups, st.Name)
		if st.Detail != "" {
			st.Detail += "; "
		}
		st.Detail += summary
	}
	audit.Log("LOCAL", "%s status=%s %s", st.Name, st.Status, st.Detail)
	src.Sources = append(src.Sources, st)
	return findings
}

// maybeInitialScan (lookup mode) scans soon after start when the newest
// report is older than scan.interval, so a restart or a fresh install
// doesn't wait a whole interval for the first result.
func (d *Daemon) maybeInitialScan(ctx context.Context) {
	newest := newestReport(d.cfg.Report.Dir)
	if !newest.IsZero() && time.Since(newest) < d.cfg.Scan.Interval && !d.cfg.Scan.OnStart {
		d.log.Info("initial scan skipped (recent report)", "age", time.Since(newest).Round(time.Second))
		return
	}
	if d.cfg.Scan.OnStart {
		return // the scheduler already runs one
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(15 * time.Second):
	}
	if d.sched != nil {
		d.sched.Trigger("scan")
	}
}

func newestReport(dir string) time.Time {
	var newest time.Time
	matches, _ := filepath.Glob(filepath.Join(dir, "lync-*.json"))
	for _, m := range matches {
		if fi, err := os.Stat(m); err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return newest
}

func dirSize(dir string) int64 {
	var n int64
	filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			n += fi.Size()
		}
		return nil
	})
	return n
}

// scanNotifier is the notification hook run after each full scan.
type scanNotifier interface {
	Process(ctx context.Context, facts *collector.Facts, findings []finding.Finding, src *feed.ScanSources, jsonPath, pdfPath string)
}
