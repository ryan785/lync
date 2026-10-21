package rules

import (
	"context"
	"github.com/ryan785/lync/internal/audit"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Host is the read-only view of the machine that checks inspect. Every
// file path a check uses is an absolute *host* path ("/etc/nginx/nginx.conf");
// Host maps it under Root so tests (and, later, container root
// filesystems) can point checks at a fixture directory. Commands go
// through Exec so tests can fake tool output, and so a missing tool is
// just an error, never a panic.
type Host struct {
	// Root is prepended to every host path. "" means the real "/".
	Root string
	// Exec runs a command and returns stdout. nil uses os/exec with a
	// timeout. A missing binary returns an error.
	Exec func(ctx context.Context, name string, args ...string) (string, error)
	// Meta overrides file metadata (mode/uid/gid) by host path. Tests use
	// it because Windows can't represent POSIX permissions or owners.
	Meta map[string]FileMeta
	// Links overrides symlink targets by host path (tests: /proc/<pid>/exe).
	Links map[string]string
	// Now is the clock (tests pin it).
	Now func() time.Time

	mu    sync.Mutex
	cache map[string]any
}

// FileMeta is the POSIX metadata checks care about.
type FileMeta struct {
	Mode fs.FileMode
	UID  int
	GID  int
	// HasOwner is false when the platform can't report owners.
	HasOwner bool
}

// CommandTimeout bounds every external tool a check runs.
const CommandTimeout = 20 * time.Second

// RealHost returns a Host for the running machine.
func RealHost() *Host { return &Host{} }

// Fresh returns a copy with the same root/exec/meta/clock and an empty
// memo cache. Safe on a nil receiver (returns the real host).
func (h *Host) Fresh() *Host {
	if h == nil {
		return RealHost()
	}
	return &Host{Root: h.Root, Exec: h.Exec, Meta: h.Meta, Links: h.Links, Now: h.Now}
}

func (h *Host) now() time.Time {
	if h != nil && h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// P maps a host path to the local filesystem path.
func (h *Host) P(p string) string {
	if h == nil || h.Root == "" {
		return p
	}
	return filepath.Join(h.Root, filepath.FromSlash(p))
}

// unP maps a local path under Root back to a host path.
func (h *Host) unP(local string) string {
	if h == nil || h.Root == "" {
		return filepath.ToSlash(local)
	}
	rel, err := filepath.Rel(h.Root, local)
	if err != nil {
		return filepath.ToSlash(local)
	}
	return "/" + strings.TrimPrefix(filepath.ToSlash(rel), "./")
}

func (h *Host) ReadFile(p string) ([]byte, error) { return os.ReadFile(h.P(p)) }

// ReadFileLimit reads at most n bytes.
func (h *Host) ReadFileLimit(p string, n int64) ([]byte, error) {
	f, err := os.Open(h.P(p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	m, err := f.Read(buf)
	if err != nil && m == 0 {
		return nil, err
	}
	return buf[:m], nil
}

func (h *Host) Exists(p string) bool {
	_, err := os.Lstat(h.P(p))
	return err == nil
}

func (h *Host) IsDir(p string) bool {
	fi, err := os.Stat(h.P(p))
	return err == nil && fi.IsDir()
}

// Stat returns POSIX metadata for a host path (Meta overrides first).
func (h *Host) Stat(p string) (FileMeta, error) {
	if h != nil && h.Meta != nil {
		if m, ok := h.Meta[p]; ok {
			return m, nil
		}
	}
	fi, err := os.Lstat(h.P(p))
	if err != nil {
		return FileMeta{}, err
	}
	m := FileMeta{Mode: fi.Mode()}
	if uid, gid, ok := fileOwner(fi); ok {
		m.UID, m.GID, m.HasOwner = uid, gid, true
	} else {
		// No POSIX metadata on this platform (Windows test runs report
		// every directory as 0777): assume conservative defaults so only
		// Meta overrides drive permission checks.
		perm := fs.FileMode(0o644)
		if fi.IsDir() {
			perm = 0o755
		}
		m.Mode = fi.Mode().Type() | perm
	}
	return m, nil
}

// StatFollow is Stat after resolving symlinks in the final path component
// (inside Root, so an absolute target maps under the fixture/image root).
// It returns the metadata of the target and the resolved host path. A
// symlink's own mode (always 0777 on Linux) is never what callers see.
func (h *Host) StatFollow(p string) (FileMeta, string, error) {
	cur := p
	for i := 0; i < 16; i++ {
		m, err := h.Stat(cur)
		if err != nil {
			return m, cur, err
		}
		if m.Mode&fs.ModeSymlink == 0 {
			return m, cur, nil
		}
		t, err := h.Readlink(cur)
		if err != nil {
			return FileMeta{}, cur, err
		}
		if !strings.HasPrefix(t, "/") {
			t = path.Join(path.Dir(cur), t)
		}
		cur = path.Clean(t)
	}
	return FileMeta{}, cur, fs.ErrInvalid
}

// ReadDir lists a directory; names only, sorted.
func (h *Host) ReadDir(p string) []fs.DirEntry {
	es, err := os.ReadDir(h.P(p))
	if err != nil {
		return nil
	}
	return es
}

// Glob expands a host-path pattern, returning host paths (sorted).
func (h *Host) Glob(pattern string) []string {
	ms, err := filepath.Glob(h.P(pattern))
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, h.unP(m))
	}
	sort.Strings(out)
	return out
}

func (h *Host) Readlink(p string) (string, error) {
	if h != nil && h.Links != nil {
		if t, ok := h.Links[p]; ok {
			return t, nil
		}
	}
	return os.Readlink(h.P(p))
}

// Walk visits host paths under root, depth-first, never following
// symlinks, stopping after maxEntries. fn returns filepath.SkipDir to prune.
func (h *Host) Walk(root string, maxDepth, maxEntries int, fn func(p string, d fs.DirEntry) error) {
	base := h.P(root)
	baseDepth := strings.Count(filepath.ToSlash(base), "/")
	n := 0
	_ = filepath.WalkDir(base, func(local string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		n++
		if maxEntries > 0 && n > maxEntries {
			return filepath.SkipAll
		}
		if d.IsDir() && maxDepth > 0 && strings.Count(filepath.ToSlash(local), "/")-baseDepth >= maxDepth {
			if err := fn(h.unP(local), d); err != nil {
				return err
			}
			return filepath.SkipDir
		}
		return fn(h.unP(local), d)
	})
}

// Run executes a tool with CommandTimeout. Output is stdout.
func (h *Host) Run(ctx context.Context, name string, args ...string) (string, error) {
	if h != nil && h.Exec != nil {
		return h.Exec(ctx, name, args...)
	}
	out, err := audit.Output(ctx, CommandTimeout, name, args...)
	return string(out), err
}

// once memoizes per-scan lookups (listeners, passwd, nginx config...).
func (h *Host) once(key string, fn func() any) any {
	// The lock is not held while fn runs: lookups nest (webRoots ->
	// loadNginx) and sync.Mutex isn't reentrant. Concurrent first calls
	// may both compute; the first stored value wins.
	h.mu.Lock()
	if h.cache == nil {
		h.cache = map[string]any{}
	}
	if v, ok := h.cache[key]; ok {
		h.mu.Unlock()
		return v
	}
	h.mu.Unlock()
	v := fn()
	h.mu.Lock()
	defer h.mu.Unlock()
	if prev, ok := h.cache[key]; ok {
		return prev
	}
	h.cache[key] = v
	return v
}

// ---- shared host facts ------------------------------------------------------

// Listener is one listening socket from `ss`.
type Listener struct {
	Proto string // tcp | udp
	Addr  string // as printed: 0.0.0.0, *, ::, 127.0.0.1, [::1], 10.0.0.5...
	Port  int
	Proc  string // first process name, "" if unknown
}

// Loopback reports whether the listener is bound to a loopback address.
func (l Listener) Loopback() bool {
	a := strings.Trim(l.Addr, "[]")
	if i := strings.IndexByte(a, '%'); i >= 0 {
		a = a[:i]
	}
	return strings.HasPrefix(a, "127.") || a == "::1" || a == "localhost"
}

// Wildcard reports whether the listener accepts on every address.
func (l Listener) Wildcard() bool {
	a := strings.Trim(l.Addr, "[]")
	return a == "0.0.0.0" || a == "*" || a == "::"
}

// Listeners returns TCP+UDP listeners (memoized). ok=false when ss is
// unavailable, so callers can tell "nothing listens" from "unknown".
func (h *Host) Listeners(ctx context.Context) ([]Listener, bool) {
	type res struct {
		ls []Listener
		ok bool
	}
	r := h.once("listeners", func() any {
		out, err := h.Run(ctx, "ss", "-H", "-tulnp")
		if err != nil && out == "" {
			return res{}
		}
		return res{parseSS(out), true}
	}).(res)
	return r.ls, r.ok
}

// parseSS parses `ss -H -tulnp` (Netid State Recv-Q Send-Q Local Peer Process).
func parseSS(out string) []Listener {
	var ls []Listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		proto := f[0]
		if proto != "tcp" && proto != "udp" {
			continue
		}
		addr, port, ok := splitHostPort(f[4])
		if !ok {
			continue
		}
		p, err := strconv.Atoi(port)
		if err != nil {
			continue
		}
		proc := ""
		if len(f) >= 7 {
			proc = extractProcessName(strings.Join(f[6:], " "))
		}
		ls = append(ls, Listener{Proto: proto, Addr: addr, Port: p, Proc: proc})
	}
	return ls
}

// ListeningOn reports whether anything listens on proto/port (any address).
func listeningOn(ls []Listener, proto string, port int) bool {
	for _, l := range ls {
		if l.Port == port && (proto == "" || l.Proto == proto) {
			return true
		}
	}
	return false
}

// Account is one /etc/passwd entry.
type Account struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
}

func (h *Host) Accounts() []Account {
	return h.once("passwd", func() any {
		data, err := h.ReadFile("/etc/passwd")
		if err != nil {
			return []Account(nil)
		}
		var out []Account
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Split(strings.TrimSpace(line), ":")
			if len(f) < 7 {
				continue
			}
			uid, err1 := strconv.Atoi(f[2])
			gid, err2 := strconv.Atoi(f[3])
			if err1 != nil || err2 != nil {
				continue
			}
			out = append(out, Account{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]})
		}
		return out
	}).([]Account)
}

func (h *Host) Account(name string) (Account, bool) {
	for _, a := range h.Accounts() {
		if a.Name == name {
			return a, true
		}
	}
	return Account{}, false
}

// Group is one /etc/group entry.
type Group struct {
	Name    string
	GID     int
	Members []string
}

func (h *Host) Groups() []Group {
	return h.once("group", func() any {
		data, err := h.ReadFile("/etc/group")
		if err != nil {
			return []Group(nil)
		}
		var out []Group
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Split(strings.TrimSpace(line), ":")
			if len(f) < 4 {
				continue
			}
			gid, err := strconv.Atoi(f[2])
			if err != nil {
				continue
			}
			var members []string
			for _, m := range strings.Split(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					members = append(members, m)
				}
			}
			out = append(out, Group{Name: f[0], GID: gid, Members: members})
		}
		return out
	}).([]Group)
}

// GIDsOf returns the primary + supplementary group IDs of a user.
func (h *Host) GIDsOf(a Account) map[int]bool {
	gids := map[int]bool{a.GID: true}
	for _, g := range h.Groups() {
		for _, m := range g.Members {
			if m == a.Name {
				gids[g.GID] = true
			}
		}
	}
	return gids
}

// WritableBy reports whether account a can write to path p (by mode bits).
func (h *Host) WritableBy(p string, a Account) bool {
	m, err := h.Stat(p)
	if err != nil {
		return false
	}
	return modeWritableBy(m, a.UID, h.GIDsOf(a))
}

func modeWritableBy(m FileMeta, uid int, gids map[int]bool) bool {
	perm := m.Mode.Perm()
	if perm&0o002 != 0 {
		return true
	}
	if !m.HasOwner {
		return false
	}
	if uid == 0 {
		return true
	}
	if m.UID == uid && perm&0o200 != 0 {
		return true
	}
	return gids[m.GID] && perm&0o020 != 0
}

// WorldReachable reports whether a non-owner, non-group user can read p:
// p is o+r and every ancestor directory is o+x.
func (h *Host) WorldReachable(p string) bool {
	m, err := h.Stat(p)
	if err != nil || m.Mode.Perm()&0o004 == 0 {
		return false
	}
	for dir := path.Dir(p); ; dir = path.Dir(dir) {
		dm, err := h.Stat(dir)
		if err != nil {
			return false
		}
		if dm.Mode.Perm()&0o001 == 0 {
			return false
		}
		if dir == "/" || dir == "." {
			return true
		}
	}
}

// SystemctlIsEnabled returns systemctl is-enabled output ("enabled",
// "disabled", "masked", "static"...) or "" when unknown.
func (h *Host) SystemctlIsEnabled(ctx context.Context, unit string) string {
	out, _ := h.Run(ctx, "systemctl", "is-enabled", unit)
	return strings.TrimSpace(out)
}
