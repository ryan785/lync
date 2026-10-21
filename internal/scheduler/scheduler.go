package scheduler

import (
	"context"
	"log/slog"
	"time"
)

type Job func(ctx context.Context) error

type Scheduler struct {
	log         *slog.Logger
	scanFn      Job
	syncFn      Job
	scanEvery   time.Duration
	syncEvery   time.Duration
	onStartScan bool
	triggers    chan string
}

func New(log *slog.Logger, scanEvery, syncEvery time.Duration, onStartScan bool, scanFn, syncFn Job) *Scheduler {
	return &Scheduler{
		log:         log,
		scanFn:      scanFn,
		syncFn:      syncFn,
		scanEvery:   scanEvery,
		syncEvery:   syncEvery,
		onStartScan: onStartScan,
		triggers:    make(chan string, 4),
	}
}

func (s *Scheduler) Trigger(kind string) {
	select {
	case s.triggers <- kind:
	default:
		s.log.Warn("scheduler trigger dropped (queue full)", "kind", kind)
	}
}

func (s *Scheduler) Run(ctx context.Context) {
	scanT := time.NewTicker(s.scanEvery)
	syncT := time.NewTicker(s.syncEvery)
	defer scanT.Stop()
	defer syncT.Stop()

	// Initial sync/scan decisions are owned by the daemon now (see
	// daemon.maybeInitialSync) so it can check cache freshness before
	// kicking off a multi-minute NVD fetch. The scheduler only handles
	// time-based ticks and the on-demand trigger channel.
	if s.onStartScan {
		go s.runJob(ctx, "scan-initial", s.scanFn)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-scanT.C:
			go s.runJob(ctx, "scan", s.scanFn)
		case <-syncT.C:
			go s.runJob(ctx, "sync", s.syncFn)
		case kind := <-s.triggers:
			switch kind {
			case "scan":
				go s.runJob(ctx, "scan-on-demand", s.scanFn)
			case "sync":
				go s.runJob(ctx, "sync-on-demand", s.syncFn)
			}
		}
	}
}

func (s *Scheduler) runJob(ctx context.Context, label string, fn Job) {
	start := time.Now()
	s.log.Info("job start", "job", label)
	if err := fn(ctx); err != nil {
		s.log.Error("job failed", "job", label, "err", err, "duration", time.Since(start))
		return
	}
	s.log.Info("job complete", "job", label, "duration", time.Since(start))
}
