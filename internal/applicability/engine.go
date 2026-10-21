package applicability

import (
	"context"
	"log/slog"
	"sync"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

type Config struct {
	// SuppressOn contains statuses that cause a finding to be dropped from
	// the report. Defaults to {NotAffected, DeferredOrWontFix} — the user
	// can narrow this via lync.yaml if they want to see deferred items.
	SuppressOn []Status
	// Concurrency caps how many judges can fetch network data in parallel.
	Concurrency int
	// Enabled — when false, Filter is a no-op (useful for debugging matcher
	// output without applicability filtering).
	Enabled bool
}

func DefaultConfig() Config {
	return Config{
		SuppressOn:  []Status{StatusNotAffected, StatusDeferredOrWontFix},
		Concurrency: 5,
		Enabled:     true,
	}
}

type Engine struct {
	judges []Judge
	cfg    Config
	log    *slog.Logger
}

func NewEngine(judges []Judge, cfg Config, log *slog.Logger) *Engine {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	return &Engine{judges: judges, cfg: cfg, log: log}
}

type Stats struct {
	Evaluated         int
	Suppressed        int
	SuppressedByJudge map[string]int
}

// Filter consults every judge that applies to the host. A finding is dropped
// if any judge returns a status listed in Config.SuppressOn. Returns the kept
// findings and aggregate stats.
func (e *Engine) Filter(ctx context.Context, findings []finding.Finding, facts *collector.Facts) ([]finding.Finding, Stats) {
	stats := Stats{SuppressedByJudge: map[string]int{}}
	if !e.cfg.Enabled || len(e.judges) == 0 || len(findings) == 0 {
		return findings, stats
	}
	var active []Judge
	for _, j := range e.judges {
		if j.AppliesTo(facts.OS) {
			active = append(active, j)
		}
	}
	if len(active) == 0 {
		return findings, stats
	}

	suppress := make(map[Status]bool, len(e.cfg.SuppressOn))
	for _, s := range e.cfg.SuppressOn {
		suppress[s] = true
	}

	type result struct {
		idx        int
		drop       bool
		dropJudge  string
		dropReason string
		annotate   *Verdict // future use — set Severity/Remediation
	}

	jobs := make(chan int)
	resultsCh := make(chan result, len(findings))
	var wg sync.WaitGroup
	for w := 0; w < e.cfg.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				f := findings[idx]
				r := result{idx: idx}
				for _, j := range active {
					v, err := j.Evaluate(ctx, f.CVE, f.Package, facts)
					if err != nil {
						e.log.Debug("judge error", "judge", j.Name(), "cve", f.CVE, "err", err)
						continue
					}
					if suppress[v.Status] {
						r.drop = true
						r.dropJudge = v.Judge
						r.dropReason = v.Reason
						break
					}
				}
				resultsCh <- r
			}
		}()
	}
	go func() {
		for i := range findings {
			jobs <- i
		}
		close(jobs)
	}()
	wg.Wait()
	close(resultsCh)

	keepMask := make([]bool, len(findings))
	for i := range keepMask {
		keepMask[i] = true
	}
	for r := range resultsCh {
		stats.Evaluated++
		if r.drop {
			keepMask[r.idx] = false
			stats.Suppressed++
			stats.SuppressedByJudge[r.dropJudge]++
			e.log.Debug("finding suppressed",
				"cve", findings[r.idx].CVE,
				"package", findings[r.idx].Package,
				"judge", r.dropJudge,
				"reason", r.dropReason)
		}
	}

	kept := make([]finding.Finding, 0, len(findings)-stats.Suppressed)
	for i, f := range findings {
		if keepMask[i] {
			kept = append(kept, f)
		}
	}
	e.log.Info("applicability filter complete",
		"evaluated", stats.Evaluated,
		"suppressed", stats.Suppressed,
		"by_judge", stats.SuppressedByJudge,
		"remaining", len(kept))
	return kept, stats
}
