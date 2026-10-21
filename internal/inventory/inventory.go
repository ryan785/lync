// Package inventory finds application components installed outside the
// OS package manager: language lockfiles and manifests (npm, PyPI,
// Packagist, Maven, Go, crates.io, RubyGems, NuGet), installed package
// metadata (site-packages, global node_modules, gem specifications), Go and
// cargo-auditable binaries, web applications (WordPress core, plugins and
// themes; Pterodactyl panel) and, opt-in, running container images.
//
// Collection is read-only and bounded: it walks a configurable set of roots
// with a depth limit, an entry limit, a per-file size cap and a total time
// budget, never follows symlinks, and skips pseudo filesystems, network
// mounts and container storage. Only package names and versions are
// extracted; file contents (configuration, .env files, credentials) never
// reach the output.
//
// Components use OSV ecosystem names so they can be checked against
// OSV.dev with QueryOSV and turned into findings with Findings.
package inventory

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/rules"
)

// OSV ecosystem names (https://ossf.github.io/osv-schema/#affectedpackage-field)
// plus a few application types OSV.dev does not index.
const (
	EcoNPM       = "npm"
	EcoPyPI      = "PyPI"
	EcoMaven     = "Maven"
	EcoPackagist = "Packagist"
	EcoGo        = "Go"
	EcoCrates    = "crates.io"
	EcoRubyGems  = "RubyGems"
	EcoNuGet     = "NuGet"

	// Not OSV ecosystems: inventoried for visibility, never sent to OSV.
	EcoWordPress       = "WordPress"
	EcoWordPressPlugin = "WordPress:plugin"
	EcoWordPressTheme  = "WordPress:theme"
	EcoContainerImage  = "container-image"
)

// Source says what kind of evidence a component came from.
const (
	SourceLockfile = "lockfile" // resolved dependency lock (package-lock.json, composer.lock...)
	SourceManifest = "manifest" // pinned manifest (requirements.txt) or archive metadata (pom.properties)
	SourceBinary   = "binary"   // embedded build info in an executable
	SourceMetadata = "metadata" // installed package metadata (dist-info, package.json, gemspec, image inspect)
)

// Scope says where a component lives.
const (
	ScopeSystem    = "system"    // host-wide install (global node_modules, /usr/local, gems, binaries)
	ScopeApp       = "app"       // an application tree (/var/www, /srv, /opt, home directories)
	ScopeContainer = "container" // a running container's image
)

// Component is one package at one version, with every place it was seen.
type Component struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Paths     []string `json:"paths"`
	Source    string   `json:"source"`
	Scope     string   `json:"scope"`
	// Dev is true when every occurrence is a development-only dependency
	// (composer packages-dev, npm "dev": true, poetry dev group...).
	Dev bool `json:"dev,omitempty"`
	// Meta holds extra non-secret facts (container image digest, OS/arch,
	// binary path for Go stdlib...).
	Meta map[string]string `json:"meta,omitempty"`
}

// Key identifies a component for deduplication.
func (c Component) Key() string { return c.Ecosystem + "\x00" + c.Name + "\x00" + c.Version }

// Warning reports something skipped or unreadable.
type Warning struct {
	Kind   string `json:"kind"` // "skip" | "limit" | "error"
	Path   string `json:"path,omitempty"`
	Reason string `json:"reason"`
}

// Root is a directory to walk. Path may be a glob ("/home/*").
type Root struct {
	Path     string
	MaxDepth int // directories below Path; 0 = Options.MaxDepth
}

// Options bound a collection run. The zero value means "defaults".
type Options struct {
	Roots       []Root        // default DefaultRoots()
	MaxDepth    int           // default 10
	MaxEntries  int           // directory entries visited across all roots; default 300000
	MaxFileSize int64         // per manifest/lockfile; default 64 MiB
	MaxArchive  int64         // per jar/war/ear on disk; default 512 MiB
	MaxNested   int64         // per nested jar read into memory; default 64 MiB
	NestedDepth int           // jar-in-jar recursion; default 2
	TimeBudget  time.Duration // whole run; default 2m
	// Binaries enables Go buildinfo / cargo-auditable reads of ELF files
	// found under the roots and in systemd ExecStart= paths (default on;
	// set NoBinaries to disable).
	NoBinaries bool
	// Containers lists running docker/podman containers and inspects their
	// images (default off: it talks to the container engine).
	Containers bool
	// IncludeOSManaged keeps components the distro package manager owns
	// (python modules installed by rpm/dpkg, binaries under /usr/bin...).
	// Off by default: the OS package scan already covers them, with
	// backport-aware data.
	IncludeOSManaged bool
	// SkipPaths are extra host path prefixes never entered.
	SkipPaths []string
}

// Stats summarises a run.
type Stats struct {
	Roots       []string      `json:"roots"`
	Entries     int           `json:"entries"`
	FilesParsed int           `json:"files_parsed"`
	Skipped     int           `json:"skipped_dirs"`
	Duration    time.Duration `json:"duration"`
	Truncated   bool          `json:"truncated"` // a limit stopped the walk early
}

// Result is the full output of CollectResult.
type Result struct {
	Components []Component `json:"components"`
	Warnings   []Warning   `json:"warnings,omitempty"`
	Stats      Stats       `json:"stats"`
}

// DefaultRoots are the directories application code usually lives in.
func DefaultRoots() []Root {
	return []Root{
		{Path: "/var/www"},
		{Path: "/srv"},
		{Path: "/opt"},
		{Path: "/usr/local"},
		{Path: "/root", MaxDepth: 7},
		{Path: "/home/*", MaxDepth: 7},
		{Path: "/usr/lib/node_modules", MaxDepth: 1},
		{Path: "/usr/lib/python3*/site-packages", MaxDepth: 1},
		{Path: "/usr/lib64/python3*/site-packages", MaxDepth: 1},
		{Path: "/var/lib/gems", MaxDepth: 4},
	}
}

func (o Options) withDefaults() Options {
	if len(o.Roots) == 0 {
		o.Roots = DefaultRoots()
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 10
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 300000
	}
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = 64 << 20
	}
	if o.MaxArchive <= 0 {
		o.MaxArchive = 512 << 20
	}
	if o.MaxNested <= 0 {
		o.MaxNested = 64 << 20
	}
	if o.NestedDepth <= 0 {
		o.NestedDepth = 2
	}
	if o.TimeBudget <= 0 {
		o.TimeBudget = 2 * time.Minute
	}
	return o
}

// Collect inventories application components on h (nil = the real host).
func Collect(ctx context.Context, h *rules.Host, opts Options) ([]Component, []Warning) {
	r := CollectResult(ctx, h, opts)
	return r.Components, r.Warnings
}

// CollectResult is Collect plus run statistics.
func CollectResult(ctx context.Context, h *rules.Host, opts Options) Result {
	if h == nil {
		h = rules.RealHost()
	}
	opts = opts.withDefaults()
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, opts.TimeBudget)
	defer cancel()

	c := &collector{ctx: ctx, h: h, opts: opts}
	c.loadMounts()
	c.walkRoots()
	if !opts.NoBinaries {
		c.systemdBinaries()
	}
	if opts.Containers {
		c.containers()
	}
	c.stats.Duration = time.Since(start)
	return Result{Components: Dedupe(c.comps), Warnings: c.warns, Stats: c.stats}
}

// Dedupe merges components with the same ecosystem, name and version,
// keeping every path. The result is sorted by ecosystem, name, version.
func Dedupe(in []Component) []Component {
	idx := map[string]int{}
	var out []Component
	for _, c := range in {
		k := c.Key()
		i, ok := idx[k]
		if !ok {
			c.Paths = append([]string(nil), c.Paths...)
			if c.Meta != nil {
				m := make(map[string]string, len(c.Meta))
				for mk, mv := range c.Meta {
					m[mk] = mv
				}
				c.Meta = m
			}
			idx[k] = len(out)
			out = append(out, c)
			continue
		}
		e := &out[i]
		e.Paths = append(e.Paths, c.Paths...)
		e.Dev = e.Dev && c.Dev
		if e.Scope != c.Scope && c.Scope == ScopeApp {
			e.Scope = ScopeApp // app wins: it's what someone deployed
		}
		for mk, mv := range c.Meta {
			if e.Meta == nil {
				e.Meta = map[string]string{}
			}
			if _, ok := e.Meta[mk]; !ok {
				e.Meta[mk] = mv
			}
		}
	}
	for i := range out {
		out[i].Paths = uniqSorted(out[i].Paths)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return out
}

func uniqSorted(s []string) []string {
	sort.Strings(s)
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// scopeFor guesses system vs app from a host path.
func scopeFor(p string) string {
	switch {
	case strings.HasPrefix(p, "/usr/"), strings.HasPrefix(p, "/var/lib/gems/"):
		return ScopeSystem
	}
	return ScopeApp
}
