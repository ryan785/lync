package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func TestPkgWatchDebounce(t *testing.T) {
	events := make(chan fsnotify.Event)
	errs := make(chan error)
	status := filepath.Clean("/var/lib/dpkg/status")
	names := map[string]bool{status: true}
	fired := make(chan struct{}, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runPkgWatch(ctx, events, errs, names, 50*time.Millisecond, func() { fired <- struct{}{} })

	// A burst of writes (an upgrade) plus irrelevant lock churn: one scan.
	for i := 0; i < 5; i++ {
		events <- fsnotify.Event{Name: status, Op: fsnotify.Write}
		events <- fsnotify.Event{Name: filepath.Clean("/var/lib/dpkg/lock"), Op: fsnotify.Write}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("no scan triggered")
	}
	select {
	case <-fired:
		t.Fatal("burst triggered more than one scan")
	case <-time.After(150 * time.Millisecond):
	}
	// Reads of the database (chmod/lock files only) never trigger.
	events <- fsnotify.Event{Name: status, Op: fsnotify.Chmod}
	select {
	case <-fired:
		t.Fatal("chmod triggered a scan")
	case <-time.After(150 * time.Millisecond):
	}
}
