package daemon

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Package databases and the files in them whose change means "packages
// were installed, upgraded or removed". Reading the database (rpm -qa)
// touches only lock/-shm/__db files, which are ignored, so a scan never
// triggers itself.
var pkgDBWatch = map[string][]string{
	"/var/lib/rpm":  {"rpmdb.sqlite", "rpmdb.sqlite-wal", "Packages", "Packages.db"},
	"/var/lib/dpkg": {"status"},
	"/lib/apk/db":   {"installed"},
}

// watchPackages triggers a scan after the package database changes, once
// scan.package_change_delay has passed without further changes (an
// upgrade run touches the database many times).
func (d *Daemon) watchPackages(ctx context.Context) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		d.log.Warn("package watch unavailable", "err", err)
		return
	}
	defer w.Close()
	names := map[string]bool{}
	armed := 0
	for dir, files := range pkgDBWatch {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		if err := w.Add(dir); err != nil {
			d.log.Debug("package watch add failed", "dir", dir, "err", err)
			continue
		}
		armed++
		for _, f := range files {
			names[filepath.Join(dir, f)] = true
		}
	}
	if armed == 0 {
		d.log.Info("package watch: no package database found")
		return
	}
	d.log.Info("package watch armed", "dirs", armed, "delay", d.cfg.Scan.PackageChangeDelay)
	runPkgWatch(ctx, w.Events, w.Errors, names, d.cfg.Scan.PackageChangeDelay, func() {
		d.log.Info("package database changed; re-scanning")
		if d.sched != nil {
			d.sched.Trigger("scan")
		}
	})
}

// runPkgWatch debounces relevant events and calls fire once per quiet
// period. Split out for tests.
func runPkgWatch(ctx context.Context, events <-chan fsnotify.Event, errs <-chan error, names map[string]bool, delay time.Duration, fire func()) {
	if delay <= 0 {
		delay = 2 * time.Minute
	}
	var timer *time.Timer
	var timerC <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if !names[filepath.Clean(ev.Name)] || ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}
			if timer == nil {
				timer = time.NewTimer(delay)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(delay)
			}
			timerC = timer.C
		case <-timerC:
			timerC = nil
			fire()
		case _, ok := <-errs:
			if !ok {
				return
			}
		}
	}
}
