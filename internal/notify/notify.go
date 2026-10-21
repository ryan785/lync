// Package notify sends service-mode notifications when a scan's findings
// change: new findings (a new CVE affecting an installed package, a new
// configuration issue), fixes that became available, and resolved
// findings, plus an optional periodic digest. Channels: SMTP email and
// webhooks (generic JSON with optional HMAC signature, Slack, Discord,
// Microsoft Teams).
//
// Every channel keeps its own snapshot of what it was last told in the
// state file, so a finding is sent once per channel, a channel that was
// down catches up on the next scan, and a newly added channel starts with
// a baseline summary.
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/config"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
)

// Channel delivers one message.
type Channel interface {
	Name() string
	Send(ctx context.Context, m *Message) error
}

// Notifier diffs scans against per-channel state and sends.
type Notifier struct {
	cfg      config.NotifyConfig
	log      *slog.Logger
	channels []Channel
	version  string
	now      func() time.Time
}

// New builds the configured channels. Secrets are read at send time.
func New(cfg config.NotifyConfig, version string, log *slog.Logger) (*Notifier, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	n := &Notifier{cfg: cfg, log: log, version: version, now: time.Now}
	if cfg.Email.Enabled {
		n.channels = append(n.channels, newEmail(cfg.Email))
	}
	for i, w := range cfg.Webhooks {
		n.channels = append(n.channels, newWebhook(w, i, version))
	}
	if len(n.channels) == 0 {
		return nil, errors.New("notify.enabled is true but no email or webhook channel is configured")
	}
	return n, nil
}

// Channels returns the configured channel names.
func (n *Notifier) Channels() []string {
	var out []string
	for _, c := range n.channels {
		out = append(out, c.Name())
	}
	return out
}

func severityRank(s string) int {
	return finding.Severity(titleWord(s)).Rank()
}

func titleWord(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// MinRank is the lowest severity rank that notifies (unknown = 0).
func (n *Notifier) minRank() int {
	if n.cfg.MinSeverity == "" {
		return finding.SeverityHigh.Rank()
	}
	return severityRank(n.cfg.MinSeverity)
}

func (n *Notifier) eventOn(e string) bool {
	if len(n.cfg.Events) == 0 {
		return true
	}
	for _, x := range n.cfg.Events {
		if x == e {
			return true
		}
	}
	return false
}

// --- state -------------------------------------------------------------------

type itemState struct {
	Severity  string    `json:"severity"`
	FixedIn   string    `json:"fixed_in,omitempty"`
	Category  string    `json:"category,omitempty"`
	Title     string    `json:"title,omitempty"`
	CVE       string    `json:"cve,omitempty"`
	Package   string    `json:"package,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
}

type channelState struct {
	MinSeverity string                `json:"min_severity"`
	LastSent    time.Time             `json:"last_sent,omitempty"`
	LastDigest  time.Time             `json:"last_digest,omitempty"`
	Findings    map[string]*itemState `json:"findings"`
}

type state struct {
	Version  int                      `json:"version"`
	LastScan time.Time                `json:"last_scan"`
	Channels map[string]*channelState `json:"channels"`
}

func (n *Notifier) loadState() *state {
	st := &state{Version: 1, Channels: map[string]*channelState{}}
	data, err := os.ReadFile(n.cfg.StateFile)
	if err != nil {
		return st
	}
	var disk state
	if json.Unmarshal(data, &disk) != nil || disk.Channels == nil {
		n.log.Warn("notify state unreadable; starting fresh (channels get a baseline)", "path", n.cfg.StateFile)
		return st
	}
	return &disk
}

func (n *Notifier) saveState(st *state) error {
	if err := os.MkdirAll(filepath.Dir(n.cfg.StateFile), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return err
	}
	tmp := n.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, n.cfg.StateFile)
}

// Process runs after every full scan. It never fails the scan: errors are
// logged, and undelivered changes are retried on the next scan.
func (n *Notifier) Process(ctx context.Context, facts *collector.Facts, findings []finding.Finding, src *feed.ScanSources, jsonPath, pdfPath string) {
	results := n.process(ctx, facts, findings, src, jsonPath, pdfPath)
	for _, r := range results {
		if r.Err != nil {
			n.log.Error("notification failed (will retry next scan)", "channel", r.Channel, "event", r.Event, "err", r.Err)
		} else {
			n.log.Info("notification sent", "channel", r.Channel, "event", r.Event, "new", r.New, "fix_available", r.Fix, "resolved", r.Resolved)
		}
	}
}

// Result is one delivery attempt.
type Result struct {
	Channel  string
	Event    string
	New      int
	Fix      int
	Resolved int
	Err      error
}

func (n *Notifier) process(ctx context.Context, facts *collector.Facts, findings []finding.Finding, src *feed.ScanSources, jsonPath, pdfPath string) []Result {
	now := n.now()
	st := n.loadState()
	st.LastScan = now
	min := n.minRank()
	cur := map[string]finding.Finding{}
	for _, f := range findings {
		if f.Severity.Rank() >= min {
			cur[f.ID] = f
		}
	}
	cveComplete := src == nil || src.Complete
	minLabel := strings.ToLower(n.cfg.MinSeverity)
	if minLabel == "" {
		minLabel = "high"
	}
	base := baseMessage(facts, findings, src, jsonPath, pdfPath, minLabel, now)

	var results []Result
	for _, ch := range n.channels {
		cs := st.Channels[ch.Name()]
		baseline := cs == nil || cs.MinSeverity != minLabel
		if baseline {
			cs = &channelState{MinSeverity: minLabel, Findings: map[string]*itemState{}}
		}
		var msgs []*Message
		next := map[string]*itemState{}
		var newItems, fixItems, resolvedItems []finding.Finding
		for id, f := range cur {
			prev := cs.Findings[id]
			is := &itemState{Severity: string(f.Severity), FixedIn: f.FixedIn, Category: string(f.Category), Title: f.Title, CVE: f.CVE, Package: f.Package, FirstSeen: now}
			if prev != nil {
				is.FirstSeen = prev.FirstSeen
				if prev.FixedIn == "" && f.FixedIn != "" {
					fixItems = append(fixItems, f)
				}
			} else {
				newItems = append(newItems, f)
			}
			next[id] = is
		}
		for id, prev := range cs.Findings {
			if _, still := cur[id]; still {
				continue
			}
			// A failed lookup must not look like "everything got patched".
			if !cveComplete && prev.Category == string(finding.CategoryCVE) {
				next[id] = prev
				continue
			}
			resolvedItems = append(resolvedItems, finding.Finding{ID: id, Title: prev.Title, CVE: prev.CVE, Package: prev.Package, Severity: finding.Severity(prev.Severity), Category: finding.Category(prev.Category), FixedIn: prev.FixedIn})
		}
		sortFindings(newItems)
		sortFindings(fixItems)
		sortFindings(resolvedItems)
		if baseline {
			m := base.clone("baseline")
			m.Current = sortedValues(cur)
			msgs = append(msgs, m)
			cs.LastDigest = now
		} else {
			m := base.clone("changes")
			if n.eventOn("new") {
				m.New = newItems
			}
			if n.eventOn("fix_available") {
				m.FixAvailable = fixItems
			}
			if n.eventOn("resolved") {
				m.Resolved = resolvedItems
			}
			if len(m.New)+len(m.FixAvailable)+len(m.Resolved) > 0 {
				msgs = append(msgs, m)
			}
			if n.cfg.Digest > 0 && now.Sub(cs.LastDigest) >= n.cfg.Digest {
				d := base.clone("digest")
				d.Current = sortedValues(cur)
				msgs = append(msgs, d)
			}
		}
		ok := true
		for _, m := range msgs {
			cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			err := ch.Send(cctx, m)
			cancel()
			results = append(results, Result{Channel: ch.Name(), Event: m.Event, New: len(m.New), Fix: len(m.FixAvailable), Resolved: len(m.Resolved), Err: err})
			if err != nil {
				ok = false
				break
			}
			if m.Event == "digest" {
				cs.LastDigest = now
			}
		}
		if ok {
			if len(msgs) > 0 {
				cs.LastSent = now
			}
			cs.Findings = next
			st.Channels[ch.Name()] = cs
		} else if baseline {
			delete(st.Channels, ch.Name()) // retry the baseline next scan
		}
	}
	// Forget channels that were removed from the config.
	for name := range st.Channels {
		found := false
		for _, ch := range n.channels {
			if ch.Name() == name {
				found = true
			}
		}
		if !found {
			delete(st.Channels, name)
		}
	}
	if err := n.saveState(st); err != nil {
		n.log.Error("notify state not saved", "path", n.cfg.StateFile, "err", err)
	}
	return results
}

// Test sends a test message to every channel.
func (n *Notifier) Test(ctx context.Context, facts *collector.Facts) []Result {
	m := baseMessage(facts, nil, nil, "", "", strings.ToLower(n.cfg.MinSeverity), n.now())
	m.Event = "test"
	var out []Result
	for _, ch := range n.channels {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := ch.Send(cctx, m)
		cancel()
		out = append(out, Result{Channel: ch.Name(), Event: "test", Err: err})
	}
	return out
}

func sortFindings(fs []finding.Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		if fs[i].CVSS != fs[j].CVSS {
			return fs[i].CVSS > fs[j].CVSS
		}
		return fs[i].ID < fs[j].ID
	})
}

func sortedValues(m map[string]finding.Finding) []finding.Finding {
	out := make([]finding.Finding, 0, len(m))
	for _, f := range m {
		out = append(out, f)
	}
	sortFindings(out)
	return out
}

// readSecret returns the content of file (trimmed) or the env var.
func readSecret(file, env string) (string, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if env != "" {
		v := os.Getenv(env)
		if v == "" {
			return "", fmt.Errorf("environment variable %s is empty", env)
		}
		return v, nil
	}
	return "", nil
}
