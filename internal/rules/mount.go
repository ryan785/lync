package rules

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// MountRule checks /proc/mounts for sensitive directories missing the
// noexec / nosuid / nodev mount options that CIS-style benchmarks expect.
type MountRule struct {
	mountsPath string
}

func NewMountRule() *MountRule { return &MountRule{mountsPath: "/proc/mounts"} }

func (r *MountRule) Name() string { return "mount" }

// Expected options per sensitive mount point. A mount missing any of the
// listed options at the given level is flagged.
type mountExpectation struct {
	path     string
	required []string
	level    Level
	severity finding.Severity
}

var mountExpectations = []mountExpectation{
	{"/tmp", []string{"noexec", "nosuid", "nodev"}, LevelMedium, finding.SeverityMedium},
	{"/var/tmp", []string{"noexec", "nosuid", "nodev"}, LevelMedium, finding.SeverityMedium},
	{"/dev/shm", []string{"noexec", "nosuid", "nodev"}, LevelMedium, finding.SeverityMedium},
	{"/home", []string{"nodev"}, LevelStrict, finding.SeverityLow},
	{"/var", []string{"nodev"}, LevelStrict, finding.SeverityLow},
	{"/var/log", []string{"nodev", "nosuid", "noexec"}, LevelStrict, finding.SeverityLow},
}

func (r *MountRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	mounts, err := readMounts(r.mountsPath)
	if err != nil {
		log.Debug("mounts unreadable", "err", err)
		return nil
	}
	var out []finding.Finding
	now := time.Now()
	for _, exp := range mountExpectations {
		if exp.level > opts.Level {
			continue
		}
		m, ok := mounts[exp.path]
		if !ok {
			// /var/log might not be a separate mount; that's fine, skip.
			continue
		}
		var missing []string
		for _, req := range exp.required {
			if !m.has(req) {
				missing = append(missing, req)
			}
		}
		if len(missing) == 0 {
			continue
		}
		out = append(out, finding.Finding{
			ID:       "mount:" + exp.path + ":" + strings.Join(missing, ","),
			Category: finding.CategoryFilesystem,
			Severity: exp.severity,
			Title:    fmt.Sprintf("%s mounted without %s", exp.path, strings.Join(missing, ", ")),
			Evidence: fmt.Sprintf("%s on %s, options: %s", m.device, exp.path, m.optsRaw),
			Remediation: fmt.Sprintf("edit /etc/fstab to add %s to %s mount options; `mount -o remount,%s %s` to apply",
				strings.Join(missing, ","), exp.path, strings.Join(missing, ","), exp.path),
			DetectedAt: now,
			Source:     "lync-rules",
		})
	}
	log.Debug("mount rule scanned", "level", opts.Level.String(), "findings", len(out))
	return out
}

type mount struct {
	device  string
	mountPt string
	fsType  string
	optsRaw string
	opts    map[string]bool
}

func (m mount) has(opt string) bool {
	if m.opts == nil {
		return false
	}
	return m.opts[opt]
}

func readMounts(path string) (map[string]mount, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]mount{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 4 {
			continue
		}
		m := mount{
			device:  fields[0],
			mountPt: fields[1],
			fsType:  fields[2],
			optsRaw: fields[3],
			opts:    map[string]bool{},
		}
		for _, o := range strings.Split(fields[3], ",") {
			// strip "key=value" tails — we only care about presence of flags
			if i := strings.Index(o, "="); i > 0 {
				o = o[:i]
			}
			m.opts[o] = true
		}
		out[m.mountPt] = m
	}
	return out, s.Err()
}
