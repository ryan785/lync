package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ryan785/lync/internal/audit"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// EOLRule checks the host OS itself against endoflife.date. Returns
// Critical if the running release is past its support window, Medium if
// it's within 30 days of EOL. Cached on disk so we don't hit the API on
// every scan.
type EOLRule struct {
	client   *http.Client
	cacheDir string
	cacheTTL time.Duration
}

func NewEOLRule() *EOLRule {
	return &EOLRule{
		client:   &http.Client{Timeout: 30 * time.Second},
		cacheDir: "/var/lib/lync/feeds/eol",
		cacheTTL: 24 * time.Hour,
	}
}

func (r *EOLRule) Name() string { return "eol" }

type eolEntry struct {
	Cycle       string `json:"cycle"`
	ReleaseDate string `json:"releaseDate"`
	EOL         any    `json:"eol"` // can be string date OR bool false
	LTS         bool   `json:"lts"`
}

func (r *EOLRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	product := eolProductFor(facts.OS.ID)
	if product == "" {
		return nil
	}
	major := facts.OS.VersionID
	if i := strings.Index(major, "."); i > 0 {
		major = major[:i]
	}

	cacheDir := r.cacheDir
	if opts.CacheDir != "" {
		cacheDir = filepath.Join(opts.CacheDir, "eol")
	}
	entries, err := r.fetchProduct(ctx, cacheDir, product, log)
	if err != nil || len(entries) == 0 {
		log.Debug("eol fetch failed", "product", product, "err", err)
		return nil
	}
	now := time.Now()
	for _, e := range entries {
		if e.Cycle != major && e.Cycle != facts.OS.VersionID {
			continue
		}
		switch eolVal := e.EOL.(type) {
		case bool:
			if eolVal {
				return []finding.Finding{eolFinding(facts.OS, "EOL", "Product cycle marked EOL", finding.SeverityHigh, now)}
			}
		case string:
			if eolVal == "" {
				continue
			}
			t, err := time.Parse("2006-01-02", eolVal)
			if err != nil {
				continue
			}
			switch {
			case now.After(t):
				return []finding.Finding{eolFinding(facts.OS,
					eolVal,
					fmt.Sprintf("%s %s reached end-of-life on %s (%d days ago)",
						product, e.Cycle, eolVal, int(now.Sub(t).Hours()/24)),
					finding.SeverityHigh, now)}
			case t.Sub(now) < 30*24*time.Hour:
				return []finding.Finding{eolFinding(facts.OS,
					eolVal,
					fmt.Sprintf("%s %s reaches end-of-life in %d days (%s)",
						product, e.Cycle, int(t.Sub(now).Hours()/24), eolVal),
					finding.SeverityMedium, now)}
			}
		}
	}
	return nil
}

func eolFinding(os collector.OSInfo, eol, evidence string, sev finding.Severity, now time.Time) finding.Finding {
	return finding.Finding{
		ID:          "eol:" + os.ID + ":" + os.VersionID,
		Category:    finding.CategoryEOL,
		Severity:    sev,
		Title:       "OS release past or approaching end-of-life: " + os.PrettyName,
		Evidence:    evidence,
		Remediation: "Plan an upgrade to a supported major release. EOL releases no longer receive security patches.",
		References:  []string{"https://endoflife.date/" + eolProductFor(os.ID)},
		DetectedAt:  now,
		Source:      "lync-rules",
	}
}

// eolProductFor maps /etc/os-release IDs to endoflife.date product slugs.
func eolProductFor(osID string) string {
	switch osID {
	case "rhel":
		return "rhel"
	case "rocky":
		return "rocky-linux"
	case "almalinux":
		return "almalinux"
	case "centos":
		return "centos"
	case "fedora":
		return "fedora"
	case "debian":
		return "debian"
	case "ubuntu":
		return "ubuntu"
	case "alpine":
		return "alpine"
	case "opensuse-leap":
		return "opensuse"
	case "sles":
		return "sles"
	}
	return ""
}

func (r *EOLRule) fetchProduct(ctx context.Context, cacheDir, product string, log *slog.Logger) ([]eolEntry, error) {
	cachePath := filepath.Join(cacheDir, product+".json")
	if info, err := os.Stat(cachePath); err == nil && time.Since(info.ModTime()) < r.cacheTTL {
		if data, err := os.ReadFile(cachePath); err == nil {
			var entries []eolEntry
			if err := json.Unmarshal(data, &entries); err == nil {
				return entries, nil
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://endoflife.date/api/"+product+".json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("endoflife.date http %d", resp.StatusCode)
	}
	var entries []eolEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cacheDir, 0o755); err == nil {
		if data, err := json.Marshal(entries); err == nil {
			if os.WriteFile(cachePath, data, 0o644) == nil {
				audit.FileWritten(cachePath, int64(len(data)))
			}
		}
	}
	return entries, nil
}
