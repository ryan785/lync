package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/ryan785/lync/internal/audit"
	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/config"
	"github.com/ryan785/lync/internal/daemon"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/logging"
)

// One-shot exit codes (documented in docs/RUNNER.md).
const (
	exitOK        = 0
	exitError     = 1
	exitDegraded  = 3 // report produced, but one or more feeds failed to sync
	exitCVEAffect = 10
	exitCVEMaybe  = 11
	exitCVEUnk    = 12
)

func main() {
	cfgPath := flag.String("config", "/etc/lync/lync.yaml", `path to config; "none" = built-in defaults, ignore any file`)
	once := flag.Bool("once", false, "one-shot mode: run one full scan (full feed mode: sync stale feeds first), print the JSON report to stdout, exit (no socket, scheduler or monitor)")
	cveID := flag.String("cve", "", "with -once: check a single CVE and print the verdict JSON instead of a full report")
	cacheDir := flag.String("cache-dir", "", "override feed.cache_dir (useful with -once on hosts without /var/lib/lync)")
	reportDir := flag.String("report-dir", "", "override report.dir")
	sources := flag.String("sources", "", `with -once: "auto" (feeds for this host's distro + OSV + NVD), "none" (rules only), or a comma list`)
	feedMode := flag.String("feed-mode", "", `override feed.mode: "lookup" (default; per-package/per-CVE API queries, no bulk download) or "full" (bulk feed sync)`)
	enable := flag.String("enable", "", "comma list appended to rules.enable (e.g. container:php-upload-progress)")
	auditLog := flag.String("audit-log", "", "append an audit line for every command, fetch and file write to this file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("lyncd", daemon.Version, runtime.GOOS+"/"+runtime.GOARCH)
		return
	}
	if *cveID != "" && !*once {
		fmt.Fprintln(os.Stderr, "-cve requires -once (or use `lync cve` against a running daemon)")
		os.Exit(exitError)
	}

	var auditFile io.Closer
	if *auditLog != "" {
		f, err := audit.OpenFile(*auditLog)
		if err != nil {
			fmt.Fprintln(os.Stderr, "audit log:", err)
			os.Exit(exitError)
		}
		auditFile = f
	}
	// Every feed and judge uses http.DefaultTransport: retry with backoff,
	// buffered bodies (mid-body HTTP/2 resets are retried), HTTP/1.1
	// fallback, and FETCH audit lines.
	http.DefaultTransport = audit.NewTransport()

	var cfg *config.Config
	var err error
	if *cfgPath == "none" || *cfgPath == "" {
		cfg = config.Default()
		err = cfg.Validate()
	} else {
		cfg, err = config.Load(*cfgPath)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(exitError)
	}
	if *cacheDir != "" {
		cfg.Feed.CacheDir = *cacheDir
	}
	if *feedMode != "" {
		if *feedMode != "lookup" && *feedMode != "full" {
			fmt.Fprintln(os.Stderr, "-feed-mode must be lookup or full")
			os.Exit(exitError)
		}
		cfg.Feed.Mode = *feedMode
	}
	if *reportDir != "" {
		cfg.Report.Dir = *reportDir
	}
	if *enable != "" {
		cfg.Rules.Enable = append(cfg.Rules.Enable, splitList(*enable)...)
	}
	if *sources != "" {
		names := splitList(*sources)
		if *sources == "none" {
			names = nil // collector + rules only (offline self-test)
		}
		if *sources == "auto" {
			osi := collector.ReadOSRelease()
			names = feed.AutoSourceNames(osi.ID, osi.IDLike)
		}
		var srcs []config.FeedSourceCfg
		for _, n := range names {
			srcs = append(srcs, config.FeedSourceCfg{Name: n, Enabled: true})
		}
		cfg.Feed.Sources = srcs
	}
	// NVD key from the environment so it never appears in argv / ps / logs.
	if key := os.Getenv("LYNC_NVD_KEY"); key != "" {
		for i := range cfg.Feed.Sources {
			if cfg.Feed.Sources[i].Name == "nvd" {
				cfg.Feed.Sources[i].APIKey = key
			}
		}
	}

	if *once {
		// SIGHUP too: the runner's SSH session dropping must stop the scan.
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		defer cancel()
		// stdout carries only the JSON result; logs go to stderr.
		log := logging.NewTo(os.Stderr, cfg.Log.Level, cfg.Log.Format)
		start := time.Now()
		audit.Log("LYNCD", "start version=%s mode=once feed_mode=%s cve=%q cache=%s reports=%s sources=%s enable=%s config=%s",
			daemon.Version, cfg.FeedMode(), *cveID, cfg.Feed.CacheDir, cfg.Report.Dir, sourceNames(cfg), strings.Join(cfg.Rules.Enable, ","), *cfgPath)
		res, err := daemon.New(cfg, log).RunOnce(ctx, *cveID, os.Stdout)
		code := exitOK
		switch {
		case err != nil:
			log.Error("one-shot run failed", "err", err)
			code = exitError
		case res.Verdict == "affected":
			code = exitCVEAffect
		case res.Verdict == "possibly_affected":
			code = exitCVEMaybe
		case res.Verdict == "unknown":
			code = exitCVEUnk
		case len(res.FailedSources) > 0:
			code = exitDegraded
		}
		failed := ""
		if res != nil {
			failed = strings.Join(res.FailedSources, ",")
		}
		audit.Log("LYNCD", "end exit=%d dur=%s failed_sources=%q err=%v", code, time.Since(start).Round(time.Millisecond), failed, err)
		if auditFile != nil {
			auditFile.Close()
		}
		os.Exit(code)
	}

	log := logging.New(cfg.Log.Level, cfg.Log.Format)

	// The unit file sends SIGHUP on `systemctl reload lync`. Go's default
	// action for an unhandled SIGHUP is to terminate the process, so catch
	// it. Live reload isn't implemented: validate the file so the operator
	// learns about mistakes now rather than at the next restart.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if _, err := config.Load(*cfgPath); err != nil {
					log.Error("SIGHUP: config is invalid; keeping running config", "path", *cfgPath, "err", err)
				} else {
					log.Warn("SIGHUP: config is valid, but live reload is not implemented; run `systemctl restart lync` to apply it", "path", *cfgPath)
				}
			}
		}
	}()

	d := daemon.New(cfg, log)
	if err := d.Run(ctx); err != nil {
		log.Error("daemon error", "err", err)
		os.Exit(exitError)
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sourceNames(cfg *config.Config) string {
	var n []string
	for _, s := range cfg.Feed.Sources {
		if s.Enabled {
			n = append(n, s.Name)
		}
	}
	return strings.Join(n, ",")
}
