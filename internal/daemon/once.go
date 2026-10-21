package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ryan785/lync/internal/audit"
	"github.com/ryan785/lync/internal/feed"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RunOnce is the agentless / fleet entry point: sync stale feeds, run one
// full scan (or one CVE check), write the result, exit. No IPC socket,
// scheduler or file-integrity monitor is started, so it can run on a host
// that has no lync service installed, e.g. pushed over SSH by a fleet
// collector. Exactly one of these happens:
//
//   - cveID != "": print the CVECheck JSON to out
//   - otherwise:   write the usual JSON+PDF report and print its JSON to out
func (d *Daemon) RunOnce(ctx context.Context, cveID string, out io.Writer) (*OnceResult, error) {
	d.ctx = ctx
	d.startedAt = time.Now()
	res := &OnceResult{}
	if err := d.setup(); err != nil {
		return res, err
	}
	names := make([]string, len(d.sources))
	for i, s := range d.sources {
		names[i] = s.Name()
	}
	if d.lookup != nil {
		names = d.lookup.Names()
	}
	audit.Log("FEEDS", "mode=%s active sources: %s (cache %s)", d.cfg.FeedMode(), strings.Join(names, ","), d.cfg.Feed.CacheDir)
	if d.lookup == nil {
		d.maybeInitialSync(ctx)
	}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	d.mu.Lock()
	res.FailedSources = append([]string(nil), d.failedSources...)
	d.mu.Unlock()

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	if cveID != "" {
		cr, err := d.CheckCVE(ctx, cveID)
		if err != nil {
			return res, err
		}
		res.Verdict = cr.Verdict
		if cr.Sources != nil {
			res.FailedSources = append(res.FailedSources, cr.Sources.FailedSources()...)
		}
		audit.Log("CVE", "%s verdict=%s known_by=%v installed_candidates=%d findings=%d reason=%q",
			cr.CVE, cr.Verdict, cr.KnownBy, len(cr.Installed), len(cr.Findings), cr.Reason)
		return res, enc.Encode(cr)
	}

	if err := d.runScan(ctx, Scope{}); err != nil {
		return res, err
	}
	d.mu.Lock()
	jsonPath := d.lastJSON
	res.Findings = len(d.lastFinds)
	if d.lookup != nil && d.lastSources != nil {
		res.FailedSources = append(res.FailedSources, d.lastSources.FailedSources()...)
		if len(res.FailedSources) == 0 && !d.lastSources.Complete && hasRemoteSource(d.lastSources) {
			res.FailedSources = append(res.FailedSources, "lookup")
		}
	}
	d.mu.Unlock()
	if jsonPath == "" {
		return res, fmt.Errorf("scan finished without a report")
	}
	res.ReportJSON = jsonPath
	f, err := os.Open(jsonPath)
	if err != nil {
		return res, err
	}
	defer f.Close()
	_, err = io.Copy(out, f)
	return res, err
}

// OnceResult summarizes a one-shot run for the caller's exit code.
type OnceResult struct {
	FailedSources []string
	Verdict       string // set for -cve runs
	Findings      int
	ReportJSON    string
}

// pruneReports deletes lync-*.json / lync-*.pdf report files older than
// retentionDays in dir. retentionDays <= 0 keeps everything. Returns the
// number of files removed.
func pruneReports(dir string, retentionDays int, now time.Time) (int, error) {
	if retentionDays <= 0 || dir == "" {
		return 0, nil
	}
	cutoff := now.Add(-time.Duration(retentionDays) * 24 * time.Hour)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	var firstErr error
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "lync-") ||
			!(strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".pdf")) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		audit.FileRemoved(filepath.Join(dir, name))
		removed++
	}
	return removed, firstErr
}

// hasRemoteSource: the scan depended on at least one lookup or bulk feed
// (not only the local package-manager check, as with -sources none).
func hasRemoteSource(s *feed.ScanSources) bool {
	for _, st := range s.Sources {
		if st.Kind != "local" {
			return true
		}
	}
	return false
}
