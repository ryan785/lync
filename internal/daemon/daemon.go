package daemon

import (
	"context"
	"fmt"
	"github.com/ryan785/lync/internal/audit"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	sdnotify "github.com/coreos/go-systemd/v22/daemon"

	"github.com/ryan785/lync/internal/applicability"
	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/config"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/ipc"
	"github.com/ryan785/lync/internal/lookup"
	"github.com/ryan785/lync/internal/matcher"
	"github.com/ryan785/lync/internal/monitor"
	"github.com/ryan785/lync/internal/reporter"
	"github.com/ryan785/lync/internal/rules"
	"github.com/ryan785/lync/internal/scheduler"
)

var Version = "0.1.0"

type Daemon struct {
	cfg          *config.Config
	log          *slog.Logger
	store        *feed.Store
	sources      []feed.Source
	sched        *scheduler.Scheduler
	applicEngine *applicability.Engine
	rulesEngine  *rules.Engine
	mon          *monitor.Monitor
	lookup       *lookup.Client // lookup mode; nil in full mode
	notifier     scanNotifier   // nil when notifications are off

	ctx       context.Context
	startedAt time.Time

	mu        sync.Mutex
	lastScan  time.Time
	lastSync  time.Time
	lastFinds []finding.Finding
	lastPDF   string
	lastJSON  string

	failedSources []string
	lastSources   *feed.ScanSources

	runMu     sync.Mutex
	running   map[string]RunningJob
	nextJobID int
}

// RunningJob is a scan or sync currently being executed. Exposed via IPC
// status so the CLI can show what the daemon is doing right now.
type RunningJob struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Scope     string    `json:"scope,omitempty"`
	StartedAt time.Time `json:"started_at"`
}

func New(cfg *config.Config, log *slog.Logger) *Daemon {
	return &Daemon{
		cfg:     cfg,
		log:     log,
		running: map[string]RunningJob{},
	}
}

func (d *Daemon) Run(ctx context.Context) error {
	d.ctx = ctx
	d.startedAt = time.Now()
	d.log.Info("lync starting", "version", Version)

	if err := d.setup(); err != nil {
		return err
	}

	d.mon = monitor.New(monitor.Config{
		Enabled: d.cfg.Monitor.Enabled,
		FileIntegrity: monitor.FileIntegrityConfig{
			Enabled: d.cfg.Monitor.FileIntegrity.Enabled,
			Paths:   d.cfg.Monitor.FileIntegrity.Paths,
		},
	}, d.log)
	if err := d.mon.Start(ctx); err != nil {
		d.log.Error("monitor start failed", "err", err)
	}

	srv, err := ipc.NewServer(d.cfg.IPC.Socket, d.handleIPC, d.log)
	if err != nil {
		return fmt.Errorf("ipc: %w", err)
	}
	go srv.Serve(ctx)

	d.sched = scheduler.New(d.log,
		d.cfg.Scan.Interval, d.cfg.Feed.SyncInterval, d.cfg.Scan.OnStart,
		d.runScheduledScan, d.runSync)
	go d.sched.Run(ctx)

	if d.lookup == nil {
		go d.maybeInitialSync(ctx)
	} else {
		go d.maybeInitialScan(ctx)
	}
	if d.cfg.Scan.OnPackageChange {
		go d.watchPackages(ctx)
	}

	if _, err := sdnotify.SdNotify(false, sdnotify.SdNotifyReady); err != nil {
		d.log.Debug("sd_notify ready", "err", err)
	}

	<-ctx.Done()
	_, _ = sdnotify.SdNotify(false, sdnotify.SdNotifyStopping)
	d.log.Info("shutdown")
	return nil
}

// setup builds the feed store, sources, applicability engine and rules
// engine. Shared by the long-running daemon (Run) and one-shot mode
// (RunOnce); the monitor, IPC socket and scheduler are started by Run only.
func (d *Daemon) setup() error {
	store, err := feed.NewStore(d.cfg.Feed.CacheDir)
	if err != nil {
		return fmt.Errorf("feed store: %w", err)
	}
	d.store = store

	if d.cfg.FeedMode() == feed.ModeFull {
		d.sources = feed.Build(d.cfg.Feed.Sources)
		srcNames := make([]string, len(d.sources))
		for i, s := range d.sources {
			srcNames[i] = s.Name()
		}
		d.log.Info("feed sources active", "mode", "full", "sources", srcNames)
	} else {
		d.lookup = buildLookup(d.cfg, d.log)
		d.log.Info("feed sources active", "mode", "lookup", "sources", d.lookup.Names())
	}

	d.applicEngine = buildApplicabilityEngine(d.cfg.Applicability, d.cfg.Feed.CacheDir, d.store, d.lookup, d.log)
	d.log.Info("applicability engine ready",
		"enabled", d.cfg.Applicability.Enabled,
		"suppress_on", d.cfg.Applicability.SuppressOn)

	rulesLevel := rules.ParseLevel(d.cfg.Rules.Level)
	if d.cfg.Rules.Enabled {
		d.rulesEngine = rules.NewEngineWithOptions(d.log, RulesOptions(d.cfg), rules.DefaultRules()...)
		d.log.Info("rules engine ready", "level", rulesLevel.String(), "rules", len(rules.DefaultRules()))
	} else {
		d.log.Info("rules engine disabled by config")
	}
	if d.cfg.Notify.Enabled && d.notifier == nil {
		n, err := newNotifier(d.cfg, d.log)
		if err != nil {
			return fmt.Errorf("notify: %w", err)
		}
		d.notifier = n
	}
	return nil
}

// --- job registration -------------------------------------------------------

func (d *Daemon) registerJob(kind, scope string) string {
	d.runMu.Lock()
	defer d.runMu.Unlock()
	d.nextJobID++
	id := fmt.Sprintf("%s-%d", kind, d.nextJobID)
	d.running[id] = RunningJob{
		ID:        id,
		Kind:      kind,
		Scope:     scope,
		StartedAt: time.Now(),
	}
	return id
}

func (d *Daemon) unregisterJob(id string) {
	d.runMu.Lock()
	defer d.runMu.Unlock()
	delete(d.running, id)
}

func (d *Daemon) snapshotJobs() []RunningJob {
	d.runMu.Lock()
	defer d.runMu.Unlock()
	out := make([]RunningJob, 0, len(d.running))
	for _, j := range d.running {
		out = append(out, j)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.Before(out[j].StartedAt) })
	return out
}

// --- scan / sync ------------------------------------------------------------

// runScheduledScan is the scheduler entry point — always a full scan.
func (d *Daemon) runScheduledScan(ctx context.Context) error {
	return d.runScan(ctx, Scope{})
}

func (d *Daemon) runScan(ctx context.Context, scope Scope) error {
	id := d.registerJob("scan", scope.Describe())
	defer d.unregisterJob(id)

	facts, err := collector.Collect(ctx, d.log)
	if err != nil {
		return err
	}
	audit.Log("FACTS", "hostname=%s os=%q kernel=%s arch=%s packages=%d running_services=%d",
		facts.Hostname, facts.OS.PrettyName, facts.Kernel.Release, facts.Kernel.Machine, len(facts.Packages), len(facts.Services))
	scoped := scope.Apply(facts)
	if !scope.IsAll() {
		d.log.Info("scan scope applied",
			"scope", scope.Describe(),
			"packages_in_scope", len(scoped.Packages),
			"packages_total", len(facts.Packages))
	}

	all, sources := d.gatherVulns(ctx, scoped)

	findings := matcher.Match(scoped, all, d.log)
	audit.Log("MATCH", "vulns=%d candidate_findings=%d", len(all), len(findings))
	findings, applicStats := d.applicEngine.Filter(ctx, findings, scoped)
	audit.Log("APPLIC", "evaluated=%d suppressed=%d by_judge=%v", applicStats.Evaluated, applicStats.Suppressed, applicStats.SuppressedByJudge)
	findings = matcher.EnrichSeverity(findings, all)
	if d.cfg.Feed.LocalCheck && scope.IsAll() {
		findings = d.localCrossCheck(ctx, scoped, findings, sources)
	}
	var coverage []finding.PackCoverage
	if scope.IsAll() && d.rulesEngine != nil {
		// Rules don't depend on the feed cache and aren't scoped to
		// a single package; only run them on full-host scans.
		findings = append(findings, d.rulesEngine.Run(ctx, scoped)...)
		coverage = d.rulesEngine.Coverage()
	}
	var inv *reporter.InventorySummary
	if scope.IsAll() && d.cfg.Inventory.Enabled {
		var invFindings []finding.Finding
		inv, invFindings = d.runInventory(ctx, sources)
		findings = append(findings, invFindings...)
	}
	if scope.IsAll() && d.mon != nil {
		findings = append(findings, d.mon.Drain()...)
	}
	if !sources.Complete {
		audit.Log("INCOMPLETE", "CVE section incomplete: %s", strings.Join(sources.IncompleteReasons, "; "))
	}
	impact := reporter.ComputeImpact(scoped, findings)

	ts := time.Now().Format("2006-01-02_15-04-05")
	base := "lync-" + ts
	if !scope.IsAll() {
		base += "-" + sanitizeForFilename(scope.Describe())
	}
	jsonPath := filepath.Join(d.cfg.Report.Dir, base+".json")
	pdfPath := filepath.Join(d.cfg.Report.Dir, base+".pdf")
	// JSON is canonical — write it first, then render the PDF from that
	// authoritative artifact. `lync render <path>` regenerates PDFs from
	// historical JSON without rerunning a scan.
	rep := reporter.BuildReport(scoped, findings, impact)
	rep.DataSources = sources
	rep.Inventory = inv
	rep.Coverage = coverage
	rep.LyncVersion = Version
	if err := reporter.WriteReport(jsonPath, rep); err != nil {
		d.log.Error("write json", "err", err)
		audit.Log("REPORT", "write json failed: %v", err)
	} else {
		logFileWritten(jsonPath)
		if err := reporter.WritePDFFromJSON(jsonPath, pdfPath); err != nil {
			d.log.Error("render pdf", "err", err)
			audit.Log("REPORT", "render pdf failed: %v", err)
		} else {
			logFileWritten(pdfPath)
		}
		txtPath := filepath.Join(d.cfg.Report.Dir, base+".txt")
		if err := reporter.WriteTextFromJSON(jsonPath, txtPath); err != nil {
			d.log.Error("render text", "err", err)
			audit.Log("REPORT", "render text failed: %v", err)
		} else {
			logFileWritten(txtPath)
		}
	}
	audit.Log("SUMMARY", "findings=%d critical=%d high=%d medium=%d low=%d info=%d unknown=%d suppressed_by_applicability=%d",
		len(findings), impact.Counts[finding.SeverityCritical], impact.Counts[finding.SeverityHigh], impact.Counts[finding.SeverityMedium],
		impact.Counts[finding.SeverityLow], impact.Counts[finding.SeverityInfo], impact.Counts[finding.SeverityUnknown], applicStats.Suppressed)
	if n, err := pruneReports(d.cfg.Report.Dir, d.cfg.Report.RetentionDays, time.Now()); err != nil {
		d.log.Warn("report retention", "err", err)
	} else if n > 0 {
		d.log.Info("pruned old reports", "files", n, "retention_days", d.cfg.Report.RetentionDays)
	}
	d.log.Info("scan complete",
		"scope", scope.Describe(),
		"findings", len(findings),
		"suppressed_by_applicability", applicStats.Suppressed,
		"unique_packages", impact.UniquePackageCount,
		"active_services_affected", len(impact.ActiveServicesAffected),
		"pdf", pdfPath, "json", jsonPath)

	// Only the full-host scan updates the "last scan" pointer; scoped scans
	// produce their own report files but don't overwrite the host baseline.
	if scope.IsAll() {
		d.mu.Lock()
		d.lastScan = time.Now()
		d.lastFinds = findings
		d.lastPDF = pdfPath
		d.lastJSON = jsonPath
		d.lastSources = sources
		d.mu.Unlock()
		if d.notifier != nil {
			d.notifier.Process(ctx, scoped, findings, sources, jsonPath, pdfPath)
		}
	}
	return nil
}

func (d *Daemon) runSync(ctx context.Context) error {
	if d.lookup != nil {
		d.log.Debug("feed.mode=lookup: nothing to sync; lookups run at scan time")
		return nil
	}
	id := d.registerJob("sync", "")
	defer d.unregisterJob(id)
	for _, src := range d.sources {
		if err := src.Sync(ctx, d.store, d.log); err != nil {
			d.log.Error("feed sync failed", "source", src.Name(), "err", err)
			continue
		}
	}
	d.mu.Lock()
	d.lastSync = time.Now()
	d.mu.Unlock()
	return nil
}

// maybeInitialSync runs only those sources whose on-disk manifest is older
// than sync_interval (or missing). This stops daemon restarts from
// re-pulling fresh data — NVD's rate-limited window can take 20+ minutes
// to refetch needlessly. The scheduled tick (every sync_interval) will
// always re-run all sources.
func (d *Daemon) maybeInitialSync(ctx context.Context) {
	var stale []feed.Source
	for _, src := range d.sources {
		m, _ := d.store.GetManifest(src.Name())
		if m == nil || time.Since(m.LastSync) > d.cfg.Feed.SyncInterval {
			stale = append(stale, src)
		} else {
			d.log.Info("initial sync skipped (cache fresh)",
				"source", src.Name(),
				"age", time.Since(m.LastSync).Round(time.Second))
			audit.Log("SYNC", "%s skipped: cache fresh (age %s, entries=%d)", src.Name(), time.Since(m.LastSync).Round(time.Second), m.EntryCount)
		}
	}
	if len(stale) == 0 {
		d.mu.Lock()
		d.lastSync = time.Now()
		d.mu.Unlock()
		return
	}
	id := d.registerJob("sync", "initial")
	defer d.unregisterJob(id)
	var failed []string
	for _, src := range stale {
		start := time.Now()
		audit.Log("SYNC", "%s start", src.Name())
		if err := src.Sync(ctx, d.store, d.log); err != nil {
			d.log.Error("initial sync failed", "source", src.Name(), "err", err)
			audit.Log("SYNC", "%s FAILED after %s: %v", src.Name(), time.Since(start).Round(time.Millisecond), err)
			failed = append(failed, src.Name())
			continue
		}
		n := 0
		if m, _ := d.store.GetManifest(src.Name()); m != nil {
			n = m.EntryCount
		}
		audit.Log("SYNC", "%s ok entries=%d dur=%s", src.Name(), n, time.Since(start).Round(time.Millisecond))
	}
	d.mu.Lock()
	d.lastSync = time.Now()
	d.failedSources = failed
	d.mu.Unlock()
}

func logFileWritten(path string) {
	if fi, err := os.Stat(path); err == nil {
		audit.FileWritten(path, fi.Size())
	}
}

// RulesOptions maps config to rules engine options (also used by `lync checks`).
func RulesOptions(cfg *config.Config) rules.Options {
	o := rules.Options{
		Level:              rules.ParseLevel(cfg.Rules.Level),
		Toggles:            rules.Toggles{Disable: cfg.Rules.Disable, Enable: cfg.Rules.Enable},
		ImageMaxAgeDays:    cfg.Rules.ImageMaxAgeDays,
		WireGuardStaleDays: cfg.Rules.WireGuardStaleDays,
		SecretScanDirs:     cfg.Rules.SecretScanDirs,
		CacheDir:           cfg.Feed.CacheDir,
	}
	if cfg.Rules.Root != "" {
		o.Host = &rules.Host{Root: cfg.Rules.Root}
	}
	return o
}

func sanitizeForFilename(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		case c == '=', c == ',':
			out = append(out, '_')
		}
	}
	return string(out)
}

// --- IPC handler ------------------------------------------------------------

func (d *Daemon) handleIPC(req ipc.Request) ipc.Response {
	switch req.Cmd {
	case ipc.CmdStatus:
		return d.statusResponse()
	case ipc.CmdScan:
		return d.handleScan(req)
	case ipc.CmdSync:
		if d.lookup != nil {
			return ipc.Response{OK: true, Data: map[string]any{"queued": "none",
				"reason": "feed.mode is lookup: there are no bulk feeds to sync; every scan queries the sources directly (run `lync scan`)"}}
		}
		d.sched.Trigger("sync")
		return ipc.Response{OK: true, Data: map[string]any{"queued": "sync"}}
	case ipc.CmdReports:
		return d.reportsResponse()
	case ipc.CmdCVE:
		id, _ := req.Args["id"].(string)
		ctx, cancel := context.WithTimeout(d.ctx, 2*time.Minute)
		defer cancel()
		res, err := d.CheckCVE(ctx, id)
		if err != nil {
			return ipc.Response{OK: false, Error: err.Error()}
		}
		return ipc.Response{OK: true, Data: res}
	default:
		return ipc.Response{OK: false, Error: "unknown command: " + req.Cmd}
	}
}

func (d *Daemon) statusResponse() ipc.Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	srcNames := make([]string, len(d.sources))
	for i, s := range d.sources {
		srcNames[i] = s.Name()
	}
	if d.lookup != nil {
		srcNames = d.lookup.Names()
	}
	complete := true
	var reasons []string
	if d.lastSources != nil {
		complete, reasons = d.lastSources.Complete, d.lastSources.IncompleteReasons
	}
	return ipc.Response{OK: true, Data: map[string]any{
		"feed_mode":          d.cfg.FeedMode(),
		"cve_data_complete":  complete,
		"incomplete_reasons": reasons,
		"notify":             d.notifier != nil,
		"version":            Version,
		"started_at":         d.startedAt,
		"last_scan":          d.lastScan,
		"last_sync":          d.lastSync,
		"findings":           len(d.lastFinds),
		"last_pdf":           d.lastPDF,
		"last_json":          d.lastJSON,
		"sources":            srcNames,
		"socket":             d.cfg.IPC.Socket,
		"report_dir":         d.cfg.Report.Dir,
		"running":            d.snapshotJobs(),
	}}
}

func (d *Daemon) handleScan(req ipc.Request) ipc.Response {
	scope := parseScope(req.Args)
	if scope.IsAll() {
		d.sched.Trigger("scan")
		return ipc.Response{OK: true, Data: map[string]any{"queued": "scan", "scope": "all"}}
	}
	// Scoped scans bypass the scheduler so the scope isn't lost in the
	// generic trigger channel.
	go func() {
		if err := d.runScan(d.ctx, scope); err != nil {
			d.log.Error("scoped scan failed", "scope", scope.Describe(), "err", err)
		}
	}()
	return ipc.Response{OK: true, Data: map[string]any{
		"queued": "scan",
		"scope":  scope.Describe(),
	}}
}

func buildApplicabilityEngine(cfg config.ApplicabilityConfig, feedCacheDir string, store *feed.Store, lk *lookup.Client, log *slog.Logger) *applicability.Engine {
	rhCacheDir := filepath.Join(feedCacheDir, "redhat", "details")
	ubCacheDir := filepath.Join(feedCacheDir, "ubuntu", "details")
	rh := applicability.NewRedHatJudge(rhCacheDir)
	if lk != nil {
		rh = applicability.NewRedHatJudgeWith(lk.Details) // same cache + TTL as the lookups
	}
	judges := []applicability.Judge{
		rh,
		applicability.NewDebianJudge(store),
		applicability.NewUbuntuJudge(ubCacheDir),
		applicability.NewSUSEJudge(),
		applicability.NewAlpineJudge(),
	}
	statusByLabel := map[string]applicability.Status{
		"not_affected":        applicability.StatusNotAffected,
		"deferred_or_wontfix": applicability.StatusDeferredOrWontFix,
		"affected":            applicability.StatusAffected,
		"unknown":             applicability.StatusUnknown,
	}
	var suppress []applicability.Status
	for _, label := range cfg.SuppressOn {
		if s, ok := statusByLabel[label]; ok {
			suppress = append(suppress, s)
		} else {
			log.Warn("unknown applicability suppress label, ignored", "label", label)
		}
	}
	if len(suppress) == 0 {
		suppress = []applicability.Status{
			applicability.StatusNotAffected,
			applicability.StatusDeferredOrWontFix,
		}
	}
	return applicability.NewEngine(judges, applicability.Config{
		Enabled:     cfg.Enabled,
		Concurrency: cfg.Concurrency,
		SuppressOn:  suppress,
	}, log)
}

func (d *Daemon) reportsResponse() ipc.Response {
	pattern := filepath.Join(d.cfg.Report.Dir, "lync-*.pdf")
	files, _ := filepath.Glob(pattern)
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	type reportEntry struct {
		Name    string    `json:"name"`
		Path    string    `json:"path"`
		Size    int64     `json:"size"`
		ModTime time.Time `json:"mtime"`
	}
	var entries []reportEntry
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		entries = append(entries, reportEntry{
			Name:    filepath.Base(f),
			Path:    f,
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}
	return ipc.Response{OK: true, Data: entries}
}
