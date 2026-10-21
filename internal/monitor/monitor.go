// Package monitor implements runtime observability — file integrity
// watching and (optionally) periodic process snapshots. Findings produced
// here flow into the next scheduled scan's report.
//
// Phase 4 scope: inotify-based file watcher only. Process-event tracking
// via netlink connector and shared-library exposure analysis are deferred
// to a later phase (would require CAP_NET_ADMIN-style privileges and adds
// non-trivial OS-specific code).
package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/ryan785/lync/internal/finding"
)

// Config controls what the monitor watches and how loudly it reports.
type Config struct {
	Enabled       bool                `yaml:"enabled"`
	FileIntegrity FileIntegrityConfig `yaml:"file_integrity"`
}

type FileIntegrityConfig struct {
	Enabled bool     `yaml:"enabled"`
	Paths   []string `yaml:"paths"`
}

func DefaultConfig() Config {
	return Config{
		Enabled: true,
		FileIntegrity: FileIntegrityConfig{
			Enabled: true,
			Paths: []string{
				"/etc/ssh/sshd_config",
				"/etc/sudoers",
				"/etc/sudoers.d",
				"/etc/passwd",
				"/etc/shadow",
				"/etc/pam.d",
				"/etc/crontab",
				"/etc/cron.d",
				"/root/.ssh/authorized_keys",
			},
		},
	}
}

type Monitor struct {
	cfg Config
	log *slog.Logger

	watcher *fsnotify.Watcher

	mu       sync.Mutex
	baseline map[string]fileFingerprint
	pending  []finding.Finding
}

type fileFingerprint struct {
	Size   int64
	Mtime  time.Time
	Mode   os.FileMode
	SHA256 string // empty when file is large/unreadable
}

func New(cfg Config, log *slog.Logger) *Monitor {
	return &Monitor{
		cfg:      cfg,
		log:      log,
		baseline: map[string]fileFingerprint{},
	}
}

func (m *Monitor) Start(ctx context.Context) error {
	if !m.cfg.Enabled || !m.cfg.FileIntegrity.Enabled || len(m.cfg.FileIntegrity.Paths) == 0 {
		m.log.Info("monitor disabled or no paths configured")
		return nil
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	m.watcher = w

	// Snapshot baseline and arm watchers.
	for _, p := range m.cfg.FileIntegrity.Paths {
		m.snapshotPath(p)
		if err := w.Add(p); err != nil {
			m.log.Debug("watcher add failed (path may not exist)", "path", p, "err", err)
		}
	}
	m.log.Info("file integrity monitor armed",
		"paths", len(m.cfg.FileIntegrity.Paths),
		"baselined_files", len(m.baseline))

	go m.loop(ctx)
	return nil
}

// Drain returns all findings accumulated since the last call, clearing the
// internal buffer. The daemon calls this each scan so monitor findings
// appear in the same report.
func (m *Monitor) Drain() []finding.Finding {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.pending
	m.pending = nil
	return out
}

func (m *Monitor) loop(ctx context.Context) {
	defer m.watcher.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			m.handleEvent(ev)
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.log.Warn("watcher error", "err", err)
		}
	}
}

func (m *Monitor) handleEvent(ev fsnotify.Event) {
	// fsnotify can fire transient events during atomic writes (some editors
	// rename a tmp file over the original). Re-stat the file to know the
	// post-event state.
	switch {
	case ev.Op&fsnotify.Write != 0, ev.Op&fsnotify.Create != 0:
		m.compareAndEmit(ev.Name, "modified")
	case ev.Op&fsnotify.Remove != 0, ev.Op&fsnotify.Rename != 0:
		m.compareAndEmit(ev.Name, "removed/renamed")
	case ev.Op&fsnotify.Chmod != 0:
		m.compareAndEmit(ev.Name, "permissions changed")
	}
}

func (m *Monitor) compareAndEmit(path, action string) {
	m.mu.Lock()
	old, hadBaseline := m.baseline[path]
	m.mu.Unlock()

	fp, err := fingerprint(path)
	if err != nil {
		// File gone — emit if we had a baseline.
		if hadBaseline {
			m.emit(finding.Finding{
				ID:          "monitor:fim:" + path,
				Category:    finding.CategoryRuntime,
				Severity:    finding.SeverityHigh,
				Title:       "Watched path " + action + ": " + path,
				Evidence:    "previously seen at mode " + old.Mode.String() + ", size " + intStr(old.Size),
				Remediation: "Investigate the change. If unexpected, restore from a known-good backup.",
				DetectedAt:  time.Now(),
				Source:      "lync-monitor",
			})
			m.mu.Lock()
			delete(m.baseline, path)
			m.mu.Unlock()
		}
		return
	}
	if !hadBaseline {
		m.mu.Lock()
		m.baseline[path] = fp
		m.mu.Unlock()
		// New file in a watched directory — emit informational note.
		m.emit(finding.Finding{
			ID:         "monitor:fim:new:" + path,
			Category:   finding.CategoryRuntime,
			Severity:   finding.SeverityMedium,
			Title:      "New file appeared in watched location: " + path,
			Evidence:   "mode " + fp.Mode.String() + ", size " + intStr(fp.Size),
			DetectedAt: time.Now(),
			Source:     "lync-monitor",
		})
		return
	}
	if fp.SHA256 != "" && old.SHA256 != "" && fp.SHA256 == old.SHA256 && fp.Mode == old.Mode {
		// Spurious event — content unchanged.
		return
	}
	m.emit(finding.Finding{
		ID:       "monitor:fim:" + path,
		Category: finding.CategoryRuntime,
		Severity: finding.SeverityHigh,
		Title:    "Watched file changed: " + path,
		Evidence: "mode " + fp.Mode.String() +
			" (was " + old.Mode.String() + "), sha256 " + shortHash(fp.SHA256) +
			" (was " + shortHash(old.SHA256) + ")",
		Remediation: "Confirm the change was authorized. Check audit logs (ausearch -f " + path + ") and consider rolling back if unexpected.",
		DetectedAt:  time.Now(),
		Source:      "lync-monitor",
	})
	m.mu.Lock()
	m.baseline[path] = fp
	m.mu.Unlock()
}

func (m *Monitor) emit(f finding.Finding) {
	m.mu.Lock()
	m.pending = append(m.pending, f)
	m.mu.Unlock()
	m.log.Info("monitor finding", "id", f.ID, "title", f.Title)
}

// snapshotPath walks path (file or directory) and records baselines for
// every file the daemon should later detect changes to.
func (m *Monitor) snapshotPath(root string) {
	info, err := os.Stat(root)
	if err != nil {
		m.log.Debug("monitor path missing", "path", root, "err", err)
		return
	}
	if !info.IsDir() {
		if fp, err := fingerprint(root); err == nil {
			m.mu.Lock()
			m.baseline[root] = fp
			m.mu.Unlock()
		}
		return
	}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if fp, err := fingerprint(path); err == nil {
			m.mu.Lock()
			m.baseline[path] = fp
			m.mu.Unlock()
		}
		return nil
	})
}

const maxHashSize = 4 * 1024 * 1024 // 4 MiB — config/auth files are far smaller

func fingerprint(path string) (fileFingerprint, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileFingerprint{}, err
	}
	fp := fileFingerprint{
		Size:  info.Size(),
		Mtime: info.ModTime(),
		Mode:  info.Mode(),
	}
	if !info.Mode().IsRegular() || info.Size() > maxHashSize {
		return fp, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fp, nil
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err == nil {
		fp.SHA256 = hex.EncodeToString(h.Sum(nil))
	}
	return fp, nil
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

func intStr(n int64) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 16)
	for n > 0 {
		buf = append([]byte{digits[n%10]}, buf...)
		n /= 10
	}
	if neg {
		return "-" + string(buf)
	}
	return string(buf)
}
