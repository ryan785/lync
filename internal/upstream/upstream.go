// Package upstream finds language runtimes installed outside the distro's
// package manager (nvm, tarballs, version managers, vendor repositories,
// container images) and matches them against the runtime project's own
// security data. Distro advisories cannot cover these installs, and
// OSV.dev has no ecosystem for most runtime cores.
//
// Each runtime is a Provider: Detect lists installs on a rules.Host (the
// real machine or a fixture root), Fetch refreshes the advisory data
// (small files, cached with conditional requests), and Match turns
// installs plus data into ordinary finding.Finding values.
//
// Node.js is the first provider. Follow-ups (docs/ROADMAP.md): the Go
// toolchain via OSV's "Go" stdlib entries, CPython and PHP.
package upstream

import (
	"context"
	"path"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/rules"
)

// Install is one runtime binary (or container image) found on the host.
type Install struct {
	Runtime string `json:"runtime"`           // "node"
	Path    string `json:"path"`              // host path of the binary, or "image:<ref>"
	Version string `json:"version"`           // e.g. 22.22.0
	Via     string `json:"via"`               // nvm, fnm, volta, asdf, mise, n, tarball, nodesource, snap, container
	PID     string `json:"pid,omitempty"`     // a running process using it
	Package string `json:"package,omitempty"` // distro package that ships it (NodeSource)
	Image   string `json:"image,omitempty"`   // container image reference
	// Containers using the image (engine:name).
	Containers []string `json:"containers,omitempty"`
}

// Enricher returns NVD-style records (CVSS, severity) for CVE ids. It may
// return fewer ids than asked for; nil means no enrichment.
type Enricher func(ctx context.Context, cves []string) map[string]feed.Vulnerability

// Env is what a provider needs for one scan.
type Env struct {
	Host    *rules.Host
	Facts   *collector.Facts
	Toggles rules.Toggles
	Now     time.Time
}

// Provider is one runtime's detection and advisory matching.
type Provider interface {
	// Name is the data-source name used in reports ("nodejs").
	Name() string
	// Detect lists the runtime's non-distro installs.
	Detect(ctx context.Context, env Env) []Install
	// Fetch refreshes the advisory data. The stat says where it came from;
	// a failed or stale fetch is reported with StatusFailed/StatusPartial.
	Fetch(ctx context.Context) feed.SourceStat
	// Match returns findings for the installs, using enrich (may be nil)
	// for CVSS scores.
	Match(ctx context.Context, env Env, installs []Install, enrich Enricher) []finding.Finding
}

// realPath resolves symlinks in the last path component (repeatedly,
// inside the host root), so /usr/local/bin/node -> ../lib/node/bin/node
// and the target dedupe to one install.
func realPath(h *rules.Host, p string) string {
	for i := 0; i < 8; i++ {
		t, err := h.Readlink(p)
		if err != nil || t == "" {
			return p
		}
		if !strings.HasPrefix(t, "/") {
			t = path.Join(path.Dir(p), t)
		}
		p = path.Clean(t)
	}
	return p
}

// homes are the directories per-user version managers live under.
func homes(h *rules.Host) []string {
	out := []string{"/root"}
	for _, d := range h.Glob("/home/*") {
		if h.IsDir(d) {
			out = append(out, d)
		}
	}
	return out
}

// distroPath reports whether p is where distro packages put binaries.
func distroPath(p string) bool {
	for _, pre := range []string{"/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/libexec/", "/usr/lib/", "/usr/lib64/", "/usr/share/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}
