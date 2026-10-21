package inventory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ryan785/lync/internal/rules"
)

// collector is the state of one Collect run.
type collector struct {
	ctx   context.Context
	h     *rules.Host
	opts  Options
	comps []Component
	warns []Warning
	stats Stats

	skipMounts map[string]string // host mount point -> reason
	stopped    bool
}

// Pseudo filesystems and container storage are never entered.
var skipPrefixes = []string{
	"/proc", "/sys", "/dev", "/run",
	"/var/lib/docker", "/var/lib/containers", "/var/lib/containerd",
	"/var/lib/kubelet/pods", "/var/lib/lxc", "/var/lib/lxd", "/snap",
}

// Directory names that hold caches, VCS data or test fixtures rather than
// deployed code. node_modules, site-packages and vendor are handled by
// their parsers instead of being walked.
var skipNames = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "__pycache__": true,
	".cache": true, ".npm": true, ".m2": true, ".gradle": true,
	".rustup": true, ".pyenv-cache": true, ".yarn-cache": true,
	"testdata": true, "__tests__": true,
}

// Filesystem types that are skipped: network, FUSE remotes, foreign/host
// shares (WSL drvfs) and image layers.
var skipFSTypes = map[string]string{
	"nfs": "network mount", "nfs4": "network mount", "cifs": "network mount",
	"smb3": "network mount", "smbfs": "network mount", "ncpfs": "network mount",
	"afs": "network mount", "ceph": "network mount", "glusterfs": "network mount",
	"lustre": "network mount", "gpfs": "network mount", "9p": "host share",
	"drvfs": "host share", "virtiofs": "host share",
	"fuse.sshfs": "network mount", "fuse.glusterfs": "network mount",
	"fuse.ceph": "network mount", "fuse.s3fs": "network mount",
	"fuse.rclone": "network mount", "fuse.gcsfuse": "network mount",
	"davfs": "network mount", "fuse.davfs": "network mount",
	"overlay": "container overlay", "aufs": "container overlay",
	"squashfs": "image layer",
}

func (c *collector) warn(kind, p, format string, args ...any) {
	c.warns = append(c.warns, Warning{Kind: kind, Path: p, Reason: fmt.Sprintf(format, args...)})
}

func (c *collector) add(comp Component) {
	if comp.Name == "" || comp.Version == "" {
		return
	}
	if comp.Scope == "" && len(comp.Paths) > 0 {
		comp.Scope = scopeFor(comp.Paths[0])
	}
	c.comps = append(c.comps, comp)
}

// local maps a host path to the local filesystem.
func (c *collector) local(p string) string { return c.h.P(p) }

// hostPath maps a local path back to a host path.
func (c *collector) hostPath(local string) string {
	if c.h.Root == "" {
		return filepath.ToSlash(local)
	}
	rel, err := filepath.Rel(c.h.Root, local)
	if err != nil {
		return filepath.ToSlash(local)
	}
	return "/" + strings.TrimPrefix(filepath.ToSlash(rel), "./")
}

// loadMounts records mount points whose filesystem type is skipped.
func (c *collector) loadMounts() {
	c.skipMounts = map[string]string{}
	data, err := c.h.ReadFileLimit("/proc/self/mounts", 4<<20)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		mp := unescapeMount(f[1])
		if mp == "/" {
			continue // a containerised scan has an overlay root; still scan it
		}
		if why, ok := skipFSTypes[f[2]]; ok {
			c.skipMounts[mp] = why + " (" + f[2] + ")"
		}
	}
}

// unescapeMount decodes the octal escapes /proc/self/mounts uses (\040).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var v int
			if _, err := fmt.Sscanf(s[i+1:i+4], "%o", &v); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hasPathPrefix(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, strings.TrimSuffix(prefix, "/")+"/")
}

// skipReason says why a host directory must not be entered ("" = enter).
func (c *collector) skipReason(p string) string {
	for _, s := range skipPrefixes {
		if hasPathPrefix(p, s) {
			return "pseudo filesystem or container storage"
		}
	}
	for _, s := range c.opts.SkipPaths {
		if hasPathPrefix(p, s) {
			return "configured skip path"
		}
	}
	if why, ok := c.skipMounts[p]; ok {
		return why
	}
	return ""
}

// expandRoots resolves globs, drops missing roots and roots nested in an
// earlier root.
func (c *collector) expandRoots() []Root {
	var out []Root
	for _, r := range c.opts.Roots {
		paths := []string{r.Path}
		if strings.ContainsAny(r.Path, "*?[") {
			paths = c.h.Glob(r.Path)
		}
		for _, p := range paths {
			p = path.Clean(p)
			if !c.h.IsDir(p) {
				continue
			}
			d := r.MaxDepth
			if d <= 0 {
				d = c.opts.MaxDepth
			}
			out = append(out, Root{Path: p, MaxDepth: d})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	var kept []Root
	for _, r := range out {
		nested := false
		for _, k := range kept {
			if hasPathPrefix(r.Path, k.Path) {
				rel := strings.Count(strings.TrimPrefix(r.Path, k.Path), "/")
				if rel+r.MaxDepth <= k.MaxDepth || r.Path == k.Path {
					nested = true
					break
				}
			}
		}
		if !nested {
			kept = append(kept, r)
		}
	}
	return kept
}

func (c *collector) budgetLeft() bool {
	if c.stopped {
		return false
	}
	if err := c.ctx.Err(); err != nil {
		c.stopped = true
		c.stats.Truncated = true
		if errors.Is(err, context.DeadlineExceeded) {
			c.warn("limit", "", "time budget %s exhausted; inventory is partial", c.opts.TimeBudget)
		} else {
			c.warn("limit", "", "collection cancelled: %v", err)
		}
		return false
	}
	if c.stats.Entries >= c.opts.MaxEntries {
		c.stopped = true
		c.stats.Truncated = true
		c.warn("limit", "", "entry limit %d reached; inventory is partial", c.opts.MaxEntries)
		return false
	}
	return true
}

func (c *collector) walkRoots() {
	for _, r := range c.expandRoots() {
		if !c.budgetLeft() {
			return
		}
		if why := c.skipReason(r.Path); why != "" {
			c.stats.Skipped++
			c.warn("skip", r.Path, "%s", why)
			continue
		}
		c.stats.Roots = append(c.stats.Roots, r.Path)
		c.walk(r)
	}
}

// walk visits one root depth-first without following symlinks.
func (c *collector) walk(r Root) {
	base := c.local(r.Path)
	baseDepth := strings.Count(filepath.ToSlash(filepath.Clean(base)), "/")
	_ = filepath.WalkDir(base, func(local string, d fs.DirEntry, err error) error {
		if !c.budgetLeft() {
			return filepath.SkipAll
		}
		c.stats.Entries++
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		hp := c.hostPath(local)
		if d.IsDir() {
			if local != base {
				if why := c.skipReason(hp); why != "" {
					c.stats.Skipped++
					if !strings.HasPrefix(why, "pseudo") {
						c.warn("skip", hp, "%s", why)
					}
					return filepath.SkipDir
				}
				if skipNames[d.Name()] || isCacheDir(hp) {
					c.stats.Skipped++
					return filepath.SkipDir
				}
			}
			if c.dir(hp, local, d.Name()) {
				return filepath.SkipDir
			}
			depth := strings.Count(filepath.ToSlash(local), "/") - baseDepth
			if depth >= r.MaxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil
		}
		c.file(hp, local, d)
		return nil
	})
}

// isCacheDir matches package-manager caches that hold source trees of every
// version ever downloaded (they are not deployed code).
func isCacheDir(p string) bool {
	for _, s := range []string{"/go/pkg/mod", "/.cargo/registry", "/.cargo/git", "/.local/share/pnpm/store", "/.yarn/berry/cache", "/.composer/cache", "/.bundle/cache"} {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	return false
}

// dir handles a directory; true means "don't descend" (already handled).
func (c *collector) dir(hp, local, name string) bool {
	switch name {
	case "node_modules":
		c.nodeModulesDir(hp, local)
		return true
	case "site-packages", "dist-packages":
		c.sitePackages(hp, local)
		return true
	case "specifications":
		if strings.Contains(hp, "gems") {
			c.gemSpecs(hp, local)
			return true
		}
	case "vendor":
		if fileExists(filepath.Join(local, "composer", "installed.json")) {
			c.composerInstalled(hp+"/composer/installed.json", filepath.Join(local, "composer", "installed.json"))
			return true
		}
	case "wp-includes", "wp-admin":
		// WordPress core trees: version is read at the site root.
		if fileExists(filepath.Join(filepath.Dir(local), "wp-includes", "version.php")) {
			return true
		}
	}
	if fileExists(filepath.Join(local, "wp-includes", "version.php")) {
		c.wordpress(hp, local)
	}
	return false
}

// file dispatches a regular file to its parser by name.
func (c *collector) file(hp, local string, d fs.DirEntry) {
	name := d.Name()
	lower := strings.ToLower(name)
	var parse func(hp, local string)
	switch {
	case name == "package-lock.json" || name == "npm-shrinkwrap.json":
		parse = c.npmLock
	case name == "yarn.lock":
		parse = c.yarnLock
	case name == "pnpm-lock.yaml":
		parse = c.pnpmLock
	case strings.HasPrefix(lower, "requirements") && strings.HasSuffix(lower, ".txt"):
		parse = c.requirements
	case name == "poetry.lock":
		parse = c.poetryLock
	case name == "Pipfile.lock":
		parse = c.pipfileLock
	case name == "composer.lock":
		parse = c.composerLock
	case name == "composer.json":
		parse = c.composerJSON
	case name == "Cargo.lock":
		parse = c.cargoLock
	case name == "Gemfile.lock" || name == "gems.locked":
		parse = c.gemfileLock
	case strings.HasSuffix(name, ".deps.json"):
		parse = c.depsJSON
	case name == "pom.properties" && strings.Contains(hp, "/META-INF/maven/"):
		parse = c.pomProperties // exploded jar/war
	case strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".war") || strings.HasSuffix(lower, ".ear"):
		c.stats.FilesParsed++
		c.archive(hp, local)
		return
	default:
		if !c.opts.NoBinaries {
			c.maybeBinary(hp, local, d)
		}
		return
	}
	fi, err := d.Info()
	if err != nil {
		return
	}
	if fi.Size() > c.opts.MaxFileSize {
		c.warn("skip", hp, "larger than %d bytes", c.opts.MaxFileSize)
		return
	}
	c.stats.FilesParsed++
	parse(hp, local)
}

// readCapped reads a local file up to MaxFileSize.
func (c *collector) readCapped(local string) ([]byte, error) {
	f, err := os.Open(local)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, c.opts.MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > c.opts.MaxFileSize {
		return nil, fmt.Errorf("larger than %d bytes", c.opts.MaxFileSize)
	}
	return data, nil
}

// read is readCapped with a warning on failure.
func (c *collector) read(hp, local string) ([]byte, bool) {
	data, err := c.readCapped(local)
	if err != nil {
		c.warn("error", hp, "read: %v", err)
		return nil, false
	}
	return data, true
}

func fileExists(local string) bool {
	fi, err := os.Stat(local)
	return err == nil && fi.Mode().IsRegular()
}

// readHead reads at most n bytes of a local file.
func readHead(local string, n int64) []byte {
	f, err := os.Open(local)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, n))
	return b
}
