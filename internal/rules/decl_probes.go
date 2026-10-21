package rules

// Probes for declarative checks. Every probe is read-only and bounded:
// files are read through Host with a size cap, commands must match the
// allowlist below and run with Host's timeout, and directory walks stop at
// max_entries. A probe that cannot run returns skip (never a finding).

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ryan785/lync/internal/matcher"
)

// obs is one observation: named fields plus the reserved _key (finding ID
// suffix) and _loc (where it was seen, for evidence).
type obs map[string]string

const (
	fKey = "_key"
	fLoc = "_loc"
)

type probeOut struct {
	obs  []obs
	skip string
}

func skipped(format string, a ...any) probeOut { return probeOut{skip: fmt.Sprintf(format, a...)} }

// probeTypes documents every probe type (also used by validation).
var probeTypes = map[string]string{
	"file":            "path globs (or from: nginx-cert...) -> path, mode, uid, gid, owner, group, type, target, size; symlinks are followed",
	"content":         "path globs + regex -> match, count, line, lineno per file (combine: one result across files)",
	"config":          "format + path + key/keys -> effective value(s); formats: " + strings.Join(configFormats, ", "),
	"sysctl":          "name -> value from /proc/sys",
	"module":          "name -> loaded, disabled, blacklisted, available, usable",
	"mount":           "name (mount points) -> options, fstype, device",
	"systemd":         "name (units) + properties -> systemctl show values",
	"listener":        "ports/proto/process -> proto, addr, port, proc, loopback, wildcard",
	"command":         "cmd (allowlisted) -> output, or one result per line (lines, line_regex named groups)",
	"package":         "name globs -> name, version (installed packages)",
	"passwd":          "accounts -> name, uid, gid, home, shell, login",
	"shadow":          "-> name, hash_type, password_set, lastchg, min, max, warn, inactive, expire (never the hash)",
	"group":           "-> name, gid, members",
	"sudoers":         "-> kind (spec|defaults), principal, principal_type, exists, nopasswd, cmds, cmds_all, setting",
	"cron":            "-> file, user, schedule, command",
	"authorized_keys": "-> user, file, type, options, has_from, has_command",
	"pg_hba":          "path -> type, database, user, address, method",
	"exports":         "-> path, client, options, wildcard",
	"process":         "process regex -> comm, uid, user, exe",
	"container":       "runtime docker|podman -> name, image, privileged, network_mode, pid_mode, ipc_mode, user, readonly_rootfs, cap_add, security_opt, docker_sock, sensitive_mounts, published_public",
	"x509":            "path globs or from: nginx|apache|postfix|dovecot -> days_left, expired, key_type, key_bits, sig_alg, self_signed, subject",
	"walk":            "roots + match/prune/max_depth/max_entries -> path, mode, uid, gid, owner, type, suid, sgid, sticky, world_writable, world_readable, size",
}

// allowedCmds is the only set of commands a declarative check may run.
// extra=true allows further non-flag arguments (unit names, IDs).
var allowedCmds = []struct {
	argv  []string
	extra bool
}{
	{[]string{"sshd", "-T"}, false},
	{[]string{"nginx", "-T"}, false},
	{[]string{"apachectl", "-M"}, false}, {[]string{"apachectl", "-S"}, false},
	{[]string{"apache2ctl", "-M"}, false}, {[]string{"apache2ctl", "-S"}, false},
	{[]string{"httpd", "-M"}, false}, {[]string{"httpd", "-S"}, false},
	{[]string{"systemctl", "is-active"}, true}, {[]string{"systemctl", "is-enabled"}, true},
	{[]string{"systemctl", "show"}, true},
	{[]string{"systemctl", "list-unit-files", "--no-legend"}, false},
	{[]string{"systemctl", "list-units", "--no-legend"}, false},
	{[]string{"auditctl", "-l"}, false}, {[]string{"auditctl", "-s"}, false},
	{[]string{"iptables", "-S"}, false}, {[]string{"ip6tables", "-S"}, false},
	{[]string{"iptables", "-S", "DOCKER-USER"}, false},
	{[]string{"nft", "list", "ruleset"}, false},
	{[]string{"ufw", "status", "verbose"}, false},
	{[]string{"firewall-cmd", "--state"}, false}, {[]string{"firewall-cmd", "--get-default-zone"}, false},
	{[]string{"firewall-cmd", "--list-all"}, false}, {[]string{"firewall-cmd", "--get-active-zones"}, false},
	{[]string{"getenforce"}, false}, {[]string{"sestatus"}, false}, {[]string{"getsebool", "-a"}, false},
	{[]string{"aa-status"}, false}, {[]string{"apparmor_status"}, false},
	{[]string{"docker", "ps", "-q"}, false}, {[]string{"docker", "inspect"}, true}, {[]string{"docker", "info", "--format", "{{json .}}"}, false},
	{[]string{"podman", "ps", "-q"}, false}, {[]string{"podman", "inspect"}, true},
	{[]string{"postconf", "-n"}, false}, {[]string{"postconf"}, false},
	{[]string{"exim", "-bP"}, false}, {[]string{"exim4", "-bP"}, false},
	{[]string{"doveconf", "-n"}, false},
	{[]string{"named-checkconf", "-p"}, false},
	{[]string{"testparm", "-s"}, false},
	{[]string{"chronyc", "-n", "sources"}, false},
	{[]string{"timedatectl", "show"}, false},
	{[]string{"mokutil", "--sb-state"}, false},
	{[]string{"fail2ban-client", "status"}, false},
	{[]string{"sudo", "-V"}, false},
	{[]string{"openssl", "version"}, false},
}

func cmdAllowed(argv []string) bool {
	for _, a := range allowedCmds {
		if len(argv) < len(a.argv) {
			continue
		}
		ok := true
		for i, s := range a.argv {
			if argv[i] != s {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if len(argv) == len(a.argv) {
			return true
		}
		if !a.extra {
			continue
		}
		for _, x := range argv[len(a.argv):] {
			if x == "" || strings.ContainsAny(x, "\n\x00") {
				return false
			}
		}
		return true
	}
	return false
}

func (p *Probe) compile() error {
	if _, ok := probeTypes[p.Type]; !ok {
		return fmt.Errorf("unknown probe type %q", p.Type)
	}
	if p.Regex != "" {
		re, err := regexp.Compile("(?m)" + p.Regex)
		if err != nil {
			return fmt.Errorf("regex: %v", err)
		}
		p.re = re
	}
	if p.LineRegex != "" {
		re, err := regexp.Compile(p.LineRegex)
		if err != nil {
			return fmt.Errorf("line_regex: %v", err)
		}
		p.lineRE = re
	}
	if p.Process != "" {
		if _, err := regexp.Compile(p.Process); err != nil {
			return fmt.Errorf("process: %v", err)
		}
	}
	for _, pth := range append(append([]string{}, p.Paths...), p.Roots...) {
		if !strings.HasPrefix(pth, "/") {
			return fmt.Errorf("path %q: want an absolute host path", pth)
		}
	}
	need := func(cond bool, what string) error {
		if !cond {
			return fmt.Errorf("%s probe needs %s", p.Type, what)
		}
		return nil
	}
	switch p.Type {
	case "file":
		return need(len(p.Paths) > 0 || len(p.From) > 0, "path or from")
	case "content":
		if err := need(len(p.Paths) > 0, "path"); err != nil {
			return err
		}
		return need(p.re != nil, "regex")
	case "config":
		if !validFormat(p.Format) {
			return fmt.Errorf("config format %q: want one of %s", p.Format, strings.Join(configFormats, ", "))
		}
		if err := need(p.Key != "" || len(p.Keys) > 0, "key or keys"); err != nil {
			return err
		}
		if formatNeedsPath(p.Format) {
			return need(len(p.Paths) > 0, "path")
		}
	case "sysctl", "module", "mount", "systemd", "package":
		return need(len(p.Name) > 0, "name")
	case "command":
		if err := need(len(p.Cmd) > 0, "cmd"); err != nil {
			return err
		}
		if !cmdAllowed(p.Cmd) {
			return fmt.Errorf("command %q is not in the read-only allowlist", strings.Join(p.Cmd, " "))
		}
	case "walk":
		return need(len(p.Roots) > 0, "roots")
	case "x509":
		return need(len(p.Paths) > 0 || len(p.From) > 0, "path or from")
	case "container":
		if p.Runtime != "docker" && p.Runtime != "podman" {
			return fmt.Errorf("container probe: runtime must be docker or podman")
		}
	}
	return nil
}

// ---- dispatch ---------------------------------------------------------------

func (env *evalEnv) runProbe(ctx context.Context, p *Probe) probeOut {
	switch p.Type {
	case "file":
		return env.probeFile(p)
	case "content":
		return env.probeContent(p)
	case "config":
		return env.probeConfig(ctx, p)
	case "sysctl":
		return env.probeSysctl(p)
	case "module":
		return env.probeModule(p)
	case "mount":
		return env.probeMount(p)
	case "systemd":
		return env.probeSystemd(ctx, p)
	case "listener":
		return env.probeListener(ctx, p)
	case "command":
		return env.probeCommand(ctx, p)
	case "package":
		return env.probePackage(p)
	case "passwd":
		return env.probePasswd()
	case "shadow":
		return env.probeShadow()
	case "group":
		return env.probeGroup()
	case "sudoers":
		return env.probeSudoers()
	case "cron":
		return env.probeCron()
	case "authorized_keys":
		return env.probeAuthorizedKeys()
	case "pg_hba":
		return env.probePgHBA(p)
	case "exports":
		return env.probeExports()
	case "process":
		return env.probeProcess(p)
	case "container":
		return env.probeContainer(ctx, p)
	case "x509":
		return env.probeX509(ctx, p)
	case "walk":
		return env.probeWalk(p)
	}
	return skipped("unknown probe %s", p.Type)
}

// ---- helpers ----------------------------------------------------------------

func hasGlob(ps []string) bool {
	for _, p := range ps {
		if strings.ContainsAny(p, "*?[") {
			return true
		}
	}
	return false
}

// expand resolves path globs to existing host paths (order kept, deduped).
func (env *evalEnv) expand(ps []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range ps {
		var ms []string
		if strings.ContainsAny(p, "*?[") {
			ms = env.h.Glob(p)
		} else if env.h.Exists(p) {
			ms = []string{p}
		}
		for _, m := range ms {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// unixMode renders permission + setuid/setgid/sticky bits as 4-digit octal.
func unixMode(m fs.FileMode) string {
	v := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		v |= 0o1000
	}
	return fmt.Sprintf("%04o", v)
}

func fileType(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "dir"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m.IsRegular():
		return "file"
	}
	return "other"
}

func (env *evalEnv) userName(uid int) string {
	for _, a := range env.h.Accounts() {
		if a.UID == uid {
			return a.Name
		}
	}
	return strconv.Itoa(uid)
}

func (env *evalEnv) groupName(gid int) string {
	for _, g := range env.h.Groups() {
		if g.GID == gid {
			return g.Name
		}
	}
	return strconv.Itoa(gid)
}

// metaObs turns file metadata into fields (owner fields only when known).
func (env *evalEnv) metaObs(o obs, m FileMeta) {
	o["mode"] = unixMode(m.Mode)
	o["type"] = fileType(m.Mode)
	b := func(v bool) string { return strconv.FormatBool(v) }
	o["suid"] = b(m.Mode&fs.ModeSetuid != 0)
	o["sgid"] = b(m.Mode&fs.ModeSetgid != 0)
	o["sticky"] = b(m.Mode&fs.ModeSticky != 0)
	o["world_writable"] = b(m.Mode.Perm()&0o002 != 0)
	o["world_readable"] = b(m.Mode.Perm()&0o004 != 0)
	if m.HasOwner {
		o["uid"] = strconv.Itoa(m.UID)
		o["gid"] = strconv.Itoa(m.GID)
		o["owner"] = env.userName(m.UID)
		o["group"] = env.groupName(m.GID)
	}
}

func readCapped(h *Host, p string, max int64) (string, bool) {
	if max <= 0 {
		max = 1 << 20
	}
	b, err := h.ReadFileLimit(p, max)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func boolStr(v bool) string { return strconv.FormatBool(v) }

// ---- file / content ---------------------------------------------------------

func (env *evalEnv) probeFile(p *Probe) probeOut {
	paths := env.expand(p.Paths)
	for _, f := range p.From {
		paths = append(paths, env.discoverTLS(f)...)
	}
	multi := len(p.Paths) > 1 || hasGlob(p.Paths) || len(p.From) > 0
	var out []obs
	seen := map[string]bool{}
	for _, pth := range paths {
		if seen[pth] {
			continue
		}
		seen[pth] = true
		o := obs{"path": pth, fLoc: pth}
		var m FileMeta
		var err error
		if p.NoFollow {
			m, err = env.h.Stat(pth)
		} else {
			var target string
			m, target, err = env.h.StatFollow(pth)
			if target != pth {
				o["target"] = target
				o[fLoc] = pth + " -> " + target
			}
		}
		if err != nil {
			continue // dangling symlink or vanished file
		}
		env.metaObs(o, m)
		if multi {
			o[fKey] = pth
		}
		out = append(out, o)
	}
	return probeOut{obs: out}
}

func (env *evalEnv) probeContent(p *Probe) probeOut {
	paths := env.expand(p.Paths)
	multi := len(p.Paths) > 1 || hasGlob(p.Paths)
	var out []obs
	var comb obs
	for _, pth := range paths {
		if env.h.IsDir(pth) {
			continue
		}
		src, ok := readCapped(env.h, pth, p.MaxBytes)
		if !ok {
			continue
		}
		if strings.IndexByte(src[:min(len(src), 512)], 0) >= 0 {
			continue // binary
		}
		locs := p.re.FindAllStringIndex(src, 1000)
		o := obs{"path": pth, "match": boolStr(len(locs) > 0), "count": strconv.Itoa(len(locs)), fLoc: pth}
		if m, _, err := env.h.StatFollow(pth); err == nil {
			env.metaObs(o, m) // lets a check combine "contains X" with "is world-readable"
		}
		if len(locs) > 0 {
			ln := strings.Count(src[:locs[0][0]], "\n") + 1
			start := strings.LastIndexByte(src[:locs[0][0]], '\n') + 1
			end := strings.IndexByte(src[locs[0][0]:], '\n')
			line := src[start:]
			if end >= 0 {
				line = src[start : locs[0][0]+end]
			}
			o["lineno"] = strconv.Itoa(ln)
			o[fLoc] = fmt.Sprintf("%s:%d", pth, ln)
			if !p.Secret {
				o["line"] = truncate(strings.TrimSpace(line), 160)
			}
		}
		if p.Combine {
			if comb == nil {
				comb = obs{"match": "false", "count": "0", fLoc: strings.Join(p.Paths, ", ")}
			}
			if o["match"] == "true" && comb["match"] == "false" {
				for k, v := range o {
					comb[k] = v
				}
			}
			continue
		}
		if multi {
			o[fKey] = pth
		}
		out = append(out, o)
	}
	if p.Combine && comb != nil {
		out = append(out, comb)
	}
	return probeOut{obs: out}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---- kernel / system --------------------------------------------------------

func (env *evalEnv) probeSysctl(p *Probe) probeOut {
	var out []obs
	for _, k := range p.Name {
		b, err := env.h.ReadFile("/proc/sys/" + strings.ReplaceAll(k, ".", "/"))
		if err != nil {
			if len(p.Name) == 1 {
				return skipped("sysctl %s not available on this kernel", k)
			}
			continue
		}
		o := obs{"value": strings.Join(strings.Fields(string(b)), " "), "name": k, fLoc: "sysctl " + k}
		if len(p.Name) > 1 {
			o[fKey] = k
		}
		out = append(out, o)
	}
	return probeOut{obs: out}
}

func modName(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), "-", "_") }

type modprobeInfo struct {
	disabled, blacklisted map[string]bool
}

func (env *evalEnv) modprobe() modprobeInfo {
	return env.h.once("decl:modprobe", func() any {
		mi := modprobeInfo{disabled: map[string]bool{}, blacklisted: map[string]bool{}}
		var files []string
		for _, d := range []string{"/usr/lib/modprobe.d", "/lib/modprobe.d", "/etc/modprobe.d", "/run/modprobe.d"} {
			files = append(files, env.h.Glob(d+"/*.conf")...)
		}
		for _, f := range files {
			src, ok := readCapped(env.h, f, 256<<10)
			if !ok {
				continue
			}
			for _, line := range strings.Split(src, "\n") {
				fs := strings.Fields(line)
				if len(fs) < 2 || strings.HasPrefix(fs[0], "#") {
					continue
				}
				switch fs[0] {
				case "blacklist":
					mi.blacklisted[modName(fs[1])] = true
				case "install":
					if len(fs) >= 3 && modInstallFalseRE.MatchString(fs[2]) {
						mi.disabled[modName(fs[1])] = true
					}
				}
			}
		}
		return mi
	}).(modprobeInfo)
}

func (env *evalEnv) kernelRelease() string {
	if b, err := env.h.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(b))
	}
	if env.facts != nil {
		return env.facts.Kernel.Release
	}
	return ""
}

// kmodIndex lists module names from modules.dep / modules.builtin.
func (env *evalEnv) kmodIndex(file string) (map[string]bool, bool) {
	type res struct {
		m  map[string]bool
		ok bool
	}
	r := env.h.once("decl:kmod:"+file, func() any {
		rel := env.kernelRelease()
		if rel == "" {
			return res{}
		}
		src, ok := readCapped(env.h, "/lib/modules/"+rel+"/"+file, 8<<20)
		if !ok {
			src, ok = readCapped(env.h, "/usr/lib/modules/"+rel+"/"+file, 8<<20)
		}
		if !ok {
			return res{}
		}
		m := map[string]bool{}
		for _, line := range strings.Split(src, "\n") {
			f, _, _ := strings.Cut(line, ":")
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			b := path.Base(f)
			if i := strings.Index(b, ".ko"); i >= 0 {
				b = b[:i]
			}
			m[modName(b)] = true
		}
		return res{m, true}
	}).(res)
	return r.m, r.ok
}

func (env *evalEnv) probeModule(p *Probe) probeOut {
	src, ok := readCapped(env.h, "/proc/modules", 1<<20)
	if !ok {
		return skipped("/proc/modules not readable")
	}
	loaded := map[string]bool{}
	for _, line := range strings.Split(src, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			loaded[modName(f[0])] = true
		}
	}
	mi := env.modprobe()
	dep, depOK := env.kmodIndex("modules.dep")
	builtin, _ := env.kmodIndex("modules.builtin")
	var out []obs
	for _, n := range p.Name {
		n = modName(n)
		avail := depOK && dep[n]
		o := obs{
			"name": n, "loaded": boolStr(loaded[n]), "disabled": boolStr(mi.disabled[n]),
			"blacklisted": boolStr(mi.blacklisted[n]), "available": boolStr(avail), "builtin": boolStr(builtin[n]),
			"usable": boolStr(loaded[n] || (avail && !mi.disabled[n])), fLoc: "module " + n,
		}
		if len(p.Name) > 1 {
			o[fKey] = n
		}
		out = append(out, o)
	}
	return probeOut{obs: out}
}

func (env *evalEnv) probeMount(p *Probe) probeOut {
	src, ok := readCapped(env.h, "/proc/mounts", 4<<20)
	if !ok {
		return skipped("/proc/mounts not readable")
	}
	mounts := map[string][]string{}
	for _, line := range strings.Split(src, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 {
			mounts[f[1]] = f // last mount on a point wins (overmounts)
		}
	}
	var out []obs
	for _, n := range p.Name {
		f, ok := mounts[n]
		if !ok {
			continue
		}
		o := obs{"path": n, "device": f[0], "fstype": f[2], "options": f[3], fLoc: "/proc/mounts " + n}
		if len(p.Name) > 1 {
			o[fKey] = n
		}
		out = append(out, o)
	}
	return probeOut{obs: out}
}

func (env *evalEnv) runCached(ctx context.Context, argv ...string) (string, error) {
	type res struct {
		out string
		err error
	}
	r := env.h.once("decl:cmd:"+strings.Join(argv, "\x00"), func() any {
		out, err := env.h.Run(ctx, argv[0], argv[1:]...)
		return res{out, err}
	}).(res)
	return r.out, r.err
}

func (env *evalEnv) probeSystemd(ctx context.Context, p *Probe) probeOut {
	props := append([]string{"LoadState", "ActiveState", "UnitFileState"}, p.Properties...)
	var out []obs
	for _, u := range p.Name {
		res, err := env.runCached(ctx, "systemctl", "show", u, "--property="+strings.Join(props, ","))
		if err != nil && res == "" {
			return skipped("systemctl unavailable")
		}
		o := obs{"unit": u, fLoc: "systemctl show " + u}
		for _, line := range strings.Split(res, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
				o[k] = v
			}
		}
		if o["LoadState"] == "not-found" || o["LoadState"] == "" {
			continue
		}
		if len(p.Name) > 1 {
			o[fKey] = u
		}
		out = append(out, o)
	}
	return probeOut{obs: out}
}

func (env *evalEnv) probeListener(ctx context.Context, p *Probe) probeOut {
	ls, ok := env.h.Listeners(ctx)
	if !ok {
		return skipped("ss unavailable")
	}
	var procRE *regexp.Regexp
	if p.Process != "" {
		procRE = regexp.MustCompile(p.Process)
	}
	byKey := map[string]obs{}
	var keys []string
	for _, l := range ls {
		if p.Proto != "" && l.Proto != p.Proto {
			continue
		}
		if len(p.Ports) > 0 {
			found := false
			for _, pt := range p.Ports {
				found = found || pt == l.Port
			}
			if !found {
				continue
			}
		}
		if procRE != nil && !procRE.MatchString(l.Proc) {
			continue
		}
		k := fmt.Sprintf("%s/%d", l.Proto, l.Port)
		o, seen := byKey[k]
		if !seen {
			o = obs{"proto": l.Proto, "port": strconv.Itoa(l.Port), "proc": l.Proc, "loopback": "true", "wildcard": "false", fKey: k}
			byKey[k] = o
			keys = append(keys, k)
		}
		if o["addr"] != "" {
			o["addr"] += ","
		}
		o["addr"] += l.Addr
		if !l.Loopback() {
			o["loopback"] = "false"
		}
		if l.Wildcard() {
			o["wildcard"] = "true"
		}
		o[fLoc] = fmt.Sprintf("%s %s:%d (%s)", l.Proto, o["addr"], l.Port, l.Proc)
	}
	var out []obs
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return probeOut{obs: out}
}

func (env *evalEnv) probeCommand(ctx context.Context, p *Probe) probeOut {
	res, err := env.runCached(ctx, p.Cmd...)
	if err != nil && strings.TrimSpace(res) == "" {
		return skipped("%s unavailable", p.Cmd[0])
	}
	loc := strings.Join(p.Cmd, " ")
	if !p.Lines {
		return probeOut{obs: []obs{{"output": truncate(strings.TrimSpace(res), 4096), fLoc: loc}}}
	}
	var out []obs
	for _, line := range strings.Split(res, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		o := obs{"line": line, fLoc: loc}
		if p.lineRE != nil {
			m := p.lineRE.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			for i, n := range p.lineRE.SubexpNames() {
				if n != "" {
					o[n] = m[i]
				}
			}
			if k, ok := o["key"]; ok {
				o[fKey] = k
			}
		}
		out = append(out, o)
	}
	return probeOut{obs: out}
}

func (env *evalEnv) probePackage(p *Probe) probeOut {
	if env.facts == nil || len(env.facts.Packages) == 0 {
		return skipped("package list unavailable")
	}
	var out []obs
	seen := map[string]bool{}
	for _, pk := range env.facts.Packages {
		for _, pat := range p.Name {
			if ok, _ := path.Match(pat, pk.Name); ok && !seen[pk.Name] {
				seen[pk.Name] = true
				out = append(out, obs{"name": pk.Name, "version": pk.NEVR(), "upstream": pk.Version, fKey: pk.Name, fLoc: "package " + pk.NEVRA()})
			}
		}
	}
	return probeOut{obs: out}
}

// ---- accounts ---------------------------------------------------------------

var (
	modInstallFalseRE = regexp.MustCompile(`^(/usr)?/s?bin/(false|true)$`)
	sudoRunasRE       = regexp.MustCompile(`^\s*\([^)]*\)`)
	sudoAliasRE       = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	ipv4RE            = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	dovecotTLSRE      = regexp.MustCompile(`(?m)^\s*ssl_(cert|key)\s*=\s*<\s*(\S+)`)
)

var noLoginShell = regexp.MustCompile(`(nologin|/false|/sync|/shutdown|/halt)$`)

func (env *evalEnv) probePasswd() probeOut {
	if !env.h.Exists("/etc/passwd") {
		return skipped("/etc/passwd not readable")
	}
	var out []obs
	for _, a := range env.h.Accounts() {
		out = append(out, obs{"name": a.Name, "uid": strconv.Itoa(a.UID), "gid": strconv.Itoa(a.GID), "home": a.Home,
			"shell": a.Shell, "login": boolStr(a.Shell != "" && !noLoginShell.MatchString(a.Shell)), fKey: a.Name, fLoc: "/etc/passwd " + a.Name})
	}
	return probeOut{obs: out}
}

func hashType(h string) string {
	switch {
	case h == "":
		return "empty"
	case strings.HasPrefix(h, "!") || strings.HasPrefix(h, "*"):
		return "locked"
	case strings.HasPrefix(h, "$1$"):
		return "md5"
	case strings.HasPrefix(h, "$2"):
		return "bcrypt"
	case strings.HasPrefix(h, "$5$"):
		return "sha256"
	case strings.HasPrefix(h, "$6$"):
		return "sha512"
	case strings.HasPrefix(h, "$y$"):
		return "yescrypt"
	case strings.HasPrefix(h, "$gy$"):
		return "gost-yescrypt"
	case len(h) == 13:
		return "des"
	}
	return "other"
}

func (env *evalEnv) probeShadow() probeOut {
	src, ok := readCapped(env.h, "/etc/shadow", 4<<20)
	if !ok {
		return skipped("/etc/shadow not readable")
	}
	var out []obs
	names := []string{"name", "", "lastchg", "min", "max", "warn", "inactive", "expire"}
	for _, line := range strings.Split(src, "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 8 {
			continue
		}
		ht := hashType(f[1])
		o := obs{"hash_type": ht, "password_set": boolStr(ht != "empty" && ht != "locked"), fKey: f[0], fLoc: "/etc/shadow " + f[0]}
		for i, n := range names {
			if n != "" && f[i] != "" {
				o[n] = f[i]
			}
		}
		out = append(out, o)
	}
	return probeOut{obs: out}
}

func (env *evalEnv) probeGroup() probeOut {
	if !env.h.Exists("/etc/group") {
		return skipped("/etc/group not readable")
	}
	var out []obs
	for _, g := range env.h.Groups() {
		out = append(out, obs{"name": g.Name, "gid": strconv.Itoa(g.GID), "members": strings.Join(g.Members, ","), fKey: g.Name, fLoc: "/etc/group " + g.Name})
	}
	return probeOut{obs: out}
}

// sudoersFiles returns /etc/sudoers plus included files, following sudo's
// includedir rules (skip names containing '.' or ending in '~').
func (env *evalEnv) sudoersFiles() []string {
	files := []string{}
	seen := map[string]bool{}
	var add func(f string, depth int)
	add = func(f string, depth int) {
		if seen[f] || depth > 4 {
			return
		}
		seen[f] = true
		src, ok := readCapped(env.h, f, 1<<20)
		if !ok {
			return
		}
		files = append(files, f)
		for _, line := range strings.Split(src, "\n") {
			fs := strings.Fields(line)
			if len(fs) != 2 {
				continue
			}
			switch fs[0] {
			case "#includedir", "@includedir":
				for _, e := range env.h.ReadDir(fs[1]) {
					n := e.Name()
					if !e.IsDir() && !strings.Contains(n, ".") && !strings.HasSuffix(n, "~") {
						add(path.Join(fs[1], n), depth+1)
					}
				}
			case "#include", "@include":
				add(fs[1], depth+1)
			}
		}
	}
	add("/etc/sudoers", 0)
	return files
}

var sudoTagRE = regexp.MustCompile(`\b(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT|MAIL|NOMAIL|FOLLOW|NOFOLLOW|INTERCEPT|NOINTERCEPT)\s*:`)

func (env *evalEnv) probeSudoers() probeOut {
	files := env.sudoersFiles()
	if len(files) == 0 {
		return skipped("/etc/sudoers not readable")
	}
	var out []obs
	for _, f := range files {
		src, _ := readCapped(env.h, f, 1<<20)
		lines := strings.Split(src, "\n")
		for i := 0; i < len(lines); i++ {
			lineNo := i + 1
			line := strings.TrimSpace(lines[i])
			for strings.HasSuffix(line, "\\") && i+1 < len(lines) {
				i++
				line = strings.TrimSuffix(line, "\\") + " " + strings.TrimSpace(lines[i])
			}
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@include") {
				continue
			}
			loc := fmt.Sprintf("%s:%d", f, lineNo)
			if strings.HasPrefix(line, "Defaults") {
				out = append(out, obs{"kind": "defaults", "setting": line, "file": f, fKey: loc, fLoc: loc})
				continue
			}
			first := strings.Fields(line)[0]
			if strings.HasSuffix(first, "_Alias") {
				continue
			}
			who, rest, ok := strings.Cut(line, " ")
			if !ok || !strings.Contains(rest, "=") {
				continue
			}
			// "alice, bob ALL=" -> principals until the host list.
			for strings.HasSuffix(who, ",") {
				r := strings.TrimSpace(rest)
				nxt, r2, _ := strings.Cut(r, " ")
				who += nxt
				rest = r2
			}
			nopw := strings.Contains(rest, "NOPASSWD")
			cmds := rest
			if j := strings.Index(rest, "="); j >= 0 {
				cmds = rest[j+1:]
			}
			cmds = strings.TrimSpace(sudoRunasRE.ReplaceAllString(cmds, ""))
			cmds = strings.TrimSpace(sudoTagRE.ReplaceAllString(cmds, ""))
			cmdsAll := false
			for _, c := range strings.Split(cmds, ",") {
				cmdsAll = cmdsAll || strings.TrimSpace(c) == "ALL"
			}
			for _, pr := range strings.Split(who, ",") {
				pr = strings.TrimSpace(pr)
				if pr == "" {
					continue
				}
				o := obs{"kind": "spec", "principal": pr, "nopasswd": boolStr(nopw), "cmds": truncate(cmds, 200),
					"cmds_all": boolStr(cmdsAll), "file": f, fKey: loc + ":" + pr, fLoc: loc + ": " + truncate(line, 200)}
				switch {
				case pr == "ALL":
					o["principal_type"] = "all"
				case strings.HasPrefix(pr, "%#"):
					o["principal_type"] = "gid"
				case strings.HasPrefix(pr, "%:"):
					o["principal_type"] = "nonunix-group"
				case strings.HasPrefix(pr, "%"):
					o["principal_type"] = "group"
					_, ok := groupByName(env.h, pr[1:])
					o["exists"] = boolStr(ok)
				case strings.HasPrefix(pr, "+"):
					o["principal_type"] = "netgroup"
				case strings.HasPrefix(pr, "#"):
					o["principal_type"] = "uid"
				case strings.ToUpper(pr) == pr && sudoAliasRE.MatchString(pr):
					o["principal_type"] = "alias"
				default:
					o["principal_type"] = "user"
					_, ok := env.h.Account(pr)
					o["exists"] = boolStr(ok)
				}
				out = append(out, o)
			}
		}
	}
	return probeOut{obs: out}
}

func groupByName(h *Host, n string) (Group, bool) {
	for _, g := range h.Groups() {
		if g.Name == n {
			return g, true
		}
	}
	return Group{}, false
}

func (env *evalEnv) probeCron() probeOut {
	var out []obs
	parse := func(f, owner string) {
		src, ok := readCapped(env.h, f, 512<<10)
		if !ok {
			return
		}
		for i, line := range strings.Split(src, "\n") {
			t := strings.TrimSpace(line)
			if t == "" || t[0] == '#' {
				continue
			}
			fields := strings.Fields(t)
			if strings.Contains(fields[0], "=") {
				continue
			}
			n := 5
			if strings.HasPrefix(fields[0], "@") {
				n = 1
			}
			user := owner
			if owner == "" {
				if len(fields) <= n {
					continue
				}
				user = fields[n]
				n++
			}
			if len(fields) <= n {
				continue
			}
			loc := fmt.Sprintf("%s:%d", f, i+1)
			out = append(out, obs{"file": f, "user": user, "schedule": strings.Join(fields[:min(n, len(fields))], " "),
				"command": truncate(strings.Join(fields[n:], " "), 300), fKey: loc, fLoc: loc})
		}
	}
	parse("/etc/crontab", "")
	for _, f := range env.h.Glob("/etc/cron.d/*") {
		parse(f, "")
	}
	for _, d := range []string{"/var/spool/cron", "/var/spool/cron/crontabs"} {
		for _, e := range env.h.ReadDir(d) {
			if !e.IsDir() {
				parse(d+"/"+e.Name(), e.Name())
			}
		}
	}
	return probeOut{obs: out}
}

func (env *evalEnv) probeAuthorizedKeys() probeOut {
	var out []obs
	seen := map[string]bool{}
	for _, a := range env.h.Accounts() {
		if a.Home == "" || a.Home == "/" {
			continue
		}
		for _, f := range []string{a.Home + "/.ssh/authorized_keys", a.Home + "/.ssh/authorized_keys2"} {
			if seen[f] {
				continue
			}
			seen[f] = true
			src, ok := readCapped(env.h, f, 1<<20)
			if !ok {
				continue
			}
			for i, line := range strings.Split(src, "\n") {
				t := strings.TrimSpace(line)
				if t == "" || t[0] == '#' {
					continue
				}
				opts, typ := "", ""
				fs := strings.Fields(t)
				for j, x := range fs {
					if strings.HasPrefix(x, "ssh-") || strings.HasPrefix(x, "ecdsa-") || strings.HasPrefix(x, "sk-") {
						typ = x
						opts = strings.Join(fs[:j], " ")
						break
					}
				}
				loc := fmt.Sprintf("%s:%d", f, i+1)
				out = append(out, obs{"user": a.Name, "uid": strconv.Itoa(a.UID), "file": f, "type": typ, "options": opts,
					"has_from": boolStr(strings.Contains(opts, "from=")), "has_command": boolStr(strings.Contains(opts, "command=")),
					fKey: loc, fLoc: loc})
			}
		}
	}
	return probeOut{obs: out}
}

func (env *evalEnv) probePgHBA(p *Probe) probeOut {
	paths := env.expand(p.Paths)
	var out []obs
	for _, f := range paths {
		src, ok := readCapped(env.h, f, 1<<20)
		if !ok {
			continue
		}
		for i, line := range strings.Split(src, "\n") {
			if j := strings.IndexByte(line, '#'); j >= 0 {
				line = line[:j]
			}
			fs := strings.Fields(line)
			if len(fs) < 4 {
				continue
			}
			o := obs{"type": fs[0], "database": fs[1], "user": fs[2], "file": f}
			rest := fs[3:]
			if fs[0] != "local" {
				if len(rest) < 2 {
					continue
				}
				o["address"] = rest[0]
				rest = rest[1:]
				if len(rest) >= 2 && ipv4RE.MatchString(rest[0]) && strings.Contains(o["address"], ".") && !strings.Contains(o["address"], "/") {
					o["address"] += "/" + rest[0] // address + netmask form
					rest = rest[1:]
				}
			}
			o["method"] = rest[0]
			loc := fmt.Sprintf("%s:%d", f, i+1)
			o[fKey], o[fLoc] = loc, loc+": "+strings.Join(fs, " ")
			out = append(out, o)
		}
	}
	return probeOut{obs: out}
}

func (env *evalEnv) probeExports() probeOut {
	files := append([]string{"/etc/exports"}, env.h.Glob("/etc/exports.d/*.exports")...)
	var out []obs
	for _, f := range files {
		src, ok := readCapped(env.h, f, 512<<10)
		if !ok {
			continue
		}
		for i, line := range strings.Split(src, "\n") {
			if j := strings.IndexByte(line, '#'); j >= 0 {
				line = line[:j]
			}
			fs := strings.Fields(line)
			if len(fs) == 0 {
				continue
			}
			clients := fs[1:]
			if len(clients) == 0 {
				clients = []string{"*"}
			}
			for _, c := range clients {
				host, opts, _ := strings.Cut(c, "(")
				opts = strings.TrimSuffix(opts, ")")
				if host == "" {
					host = "*"
				}
				loc := fmt.Sprintf("%s:%d", f, i+1)
				out = append(out, obs{"path": fs[0], "client": host, "options": opts, "wildcard": boolStr(host == "*" || host == "0.0.0.0/0" || host == "::/0"),
					fKey: fs[0] + ":" + host, fLoc: loc + ": " + fs[0] + " " + c})
			}
		}
	}
	return probeOut{obs: out}
}

type procInfo struct {
	comm, exe string
	uid       int
}

func (env *evalEnv) processes() []procInfo {
	return env.h.once("decl:procs", func() any {
		var out []procInfo
		for _, d := range env.h.ReadDir("/proc") {
			if _, err := strconv.Atoi(d.Name()); err != nil {
				continue
			}
			base := "/proc/" + d.Name()
			comm, ok := readCapped(env.h, base+"/comm", 256)
			if !ok {
				continue
			}
			pi := procInfo{comm: strings.TrimSpace(comm), uid: -1}
			if st, ok := readCapped(env.h, base+"/status", 8192); ok {
				for _, l := range strings.Split(st, "\n") {
					if strings.HasPrefix(l, "Uid:") {
						if f := strings.Fields(l); len(f) > 1 {
							pi.uid, _ = strconv.Atoi(f[1])
						}
					}
				}
			}
			if t, err := env.h.Readlink(base + "/exe"); err == nil {
				pi.exe = strings.TrimSuffix(t, " (deleted)")
			}
			out = append(out, pi)
		}
		return out
	}).([]procInfo)
}

func (env *evalEnv) probeProcess(p *Probe) probeOut {
	if !env.h.IsDir("/proc") {
		return skipped("/proc not available")
	}
	pat := p.Process
	if pat == "" && len(p.Name) > 0 {
		pat = "^(" + strings.Join(p.Name, "|") + ")$"
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return skipped("bad process pattern")
	}
	by := map[string]obs{}
	var keys []string
	for _, pi := range env.processes() {
		if !re.MatchString(pi.comm) {
			continue
		}
		k := pi.comm + ":" + strconv.Itoa(pi.uid)
		if _, ok := by[k]; ok {
			continue
		}
		user := env.userName(pi.uid)
		by[k] = obs{"comm": pi.comm, "uid": strconv.Itoa(pi.uid), "user": user, "exe": pi.exe, fKey: pi.comm, fLoc: fmt.Sprintf("process %s (user %s)", pi.comm, user)}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []obs
	for _, k := range keys {
		out = append(out, by[k])
	}
	return probeOut{obs: out}
}

// ---- containers -------------------------------------------------------------

var sensitiveMounts = []string{"/", "/etc", "/root", "/var/run", "/run", "/proc", "/sys", "/boot", "/dev", "/var/lib/docker", "/home"}

func (env *evalEnv) probeContainer(ctx context.Context, p *Probe) probeOut {
	rt := p.Runtime
	ids, err := env.runCached(ctx, rt, "ps", "-q")
	if err != nil && strings.TrimSpace(ids) == "" {
		return skipped("%s unavailable", rt)
	}
	idl := strings.Fields(ids)
	if len(idl) == 0 {
		return probeOut{}
	}
	if len(idl) > 200 {
		idl = idl[:200]
	}
	raw, err := env.runCached(ctx, append([]string{rt, "inspect"}, idl...)...)
	if err != nil && raw == "" {
		return skipped("%s inspect failed", rt)
	}
	var cs []struct {
		Name       string
		Config     struct{ Image, User string }
		HostConfig struct {
			Privileged     bool
			NetworkMode    string
			PidMode        string
			IpcMode        string
			ReadonlyRootfs bool
			CapAdd         []string
			SecurityOpt    []string
			PortBindings   map[string][]struct{ HostIp, HostPort string }
			UsernsMode     string
			Memory         int64
			RestartPolicy  struct{ Name string }
			Devices        []any
			CgroupnsMode   string
			PidsLimit      *int64
			NanoCpus       int64
		}
		Mounts []struct{ Source, Destination string }
	}
	if err := json.Unmarshal([]byte(raw), &cs); err != nil {
		return skipped("%s inspect: unparseable output", rt)
	}
	var out []obs
	for _, c := range cs {
		name := strings.TrimPrefix(c.Name, "/")
		hc := c.HostConfig
		var sens []string
		sock := false
		for _, m := range c.Mounts {
			if strings.HasSuffix(m.Source, "/docker.sock") || strings.HasSuffix(m.Source, "/podman.sock") || strings.HasSuffix(m.Source, "/containerd.sock") {
				sock = true
			}
			for _, s := range sensitiveMounts {
				if path.Clean(m.Source) == s {
					sens = append(sens, m.Source)
				}
			}
		}
		public := false
		var pubs []string
		for port, bs := range hc.PortBindings {
			for _, b := range bs {
				if b.HostIp == "" || b.HostIp == "0.0.0.0" || b.HostIp == "::" {
					public = true
					pubs = append(pubs, port)
				}
			}
		}
		sort.Strings(pubs)
		user := c.Config.User
		if user == "" {
			user = "root"
		}
		out = append(out, obs{
			"name": name, "image": c.Config.Image, "privileged": boolStr(hc.Privileged), "network_mode": hc.NetworkMode,
			"pid_mode": hc.PidMode, "ipc_mode": hc.IpcMode, "user": user, "readonly_rootfs": boolStr(hc.ReadonlyRootfs),
			"cap_add": strings.Join(hc.CapAdd, ","), "security_opt": strings.Join(hc.SecurityOpt, ","),
			"docker_sock": boolStr(sock), "sensitive_mounts": strings.Join(sens, ","), "published_public": boolStr(public),
			"published_ports": strings.Join(pubs, ","), "memory_limit": strconv.FormatInt(hc.Memory, 10),
			"restart_policy": hc.RestartPolicy.Name, "userns_mode": hc.UsernsMode,
			fKey: name, fLoc: rt + " container " + name + " (" + c.Config.Image + ")",
		})
	}
	return probeOut{obs: out}
}

// ---- TLS --------------------------------------------------------------------

// discoverTLS returns certificate or key paths referenced by service
// configs: kind is <service>-cert or <service>-key (nginx, apache, postfix,
// dovecot), or just <service> for both.
func (env *evalEnv) discoverTLS(kind string) []string {
	svc, what, _ := strings.Cut(kind, "-")
	var certs, keys []string
	ctx := context.Background()
	switch svc {
	case "nginx":
		if c := env.h.loadNginx(ctx); c != nil {
			for _, e := range nginxEntries(c)["ssl_certificate"] {
				certs = append(certs, e.val)
			}
			for _, e := range nginxEntries(c)["ssl_certificate_key"] {
				keys = append(keys, e.val)
			}
		}
	case "apache":
		ents := env.apacheEntries()
		for _, e := range ents["sslcertificatefile"] {
			certs = append(certs, e.val)
		}
		for _, e := range ents["sslcertificatekeyfile"] {
			keys = append(keys, e.val)
		}
	case "postfix":
		doc := env.kvDocs([]string{"/etc/postfix/main.cf"}, "kv", false)
		if len(doc) > 0 {
			for _, k := range []string{"smtpd_tls_cert_file", "smtpd_tls_chain_files"} {
				if e, ok := doc[0].get(k, false); ok {
					certs = append(certs, strings.Fields(strings.ReplaceAll(e.val, ",", " "))...)
				}
			}
			if e, ok := doc[0].get("smtpd_tls_key_file", false); ok {
				keys = append(keys, e.val)
			}
		}
	case "dovecot":
		for _, f := range env.expand([]string{"/etc/dovecot/dovecot.conf", "/etc/dovecot/conf.d/*.conf"}) {
			src, _ := readCapped(env.h, f, 512<<10)
			for _, m := range dovecotTLSRE.FindAllStringSubmatch(src, -1) {
				if m[1] == "cert" {
					certs = append(certs, m[2])
				} else {
					keys = append(keys, m[2])
				}
			}
		}
	}
	var out []string
	add := func(ps []string) {
		for _, p := range ps {
			p = strings.Trim(p, `"'`)
			if strings.HasPrefix(p, "/") && !strings.Contains(p, "$") && env.h.Exists(p) {
				out = append(out, p)
			}
		}
	}
	if what == "" || what == "cert" {
		add(certs)
	}
	if what == "" || what == "key" {
		add(keys)
	}
	sort.Strings(out)
	return dedupe(out)
}

func dedupe(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func (env *evalEnv) probeX509(ctx context.Context, p *Probe) probeOut {
	paths := env.expand(p.Paths)
	for _, f := range p.From {
		if !strings.Contains(f, "-") {
			f += "-cert"
		}
		paths = append(paths, env.discoverTLS(f)...)
	}
	sort.Strings(paths)
	paths = dedupe(paths)
	var out []obs
	now := env.h.now()
	for _, f := range paths {
		src, ok := readCapped(env.h, f, 256<<10)
		if !ok {
			continue
		}
		blk, rest := pem.Decode([]byte(src))
		for blk != nil && blk.Type != "CERTIFICATE" {
			blk, rest = pem.Decode(rest)
		}
		if blk == nil || blk.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			continue
		}
		kt, bits := "other", 0
		switch k := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			kt, bits = "rsa", k.N.BitLen()
		case *ecdsa.PublicKey:
			kt, bits = "ecdsa", k.Curve.Params().BitSize
		case ed25519.PublicKey:
			kt, bits = "ed25519", 256
		}
		days := int(cert.NotAfter.Sub(now).Hours() / 24)
		if cert.NotAfter.Before(now) && days == 0 {
			days = -1
		}
		self := cert.Subject.String() == cert.Issuer.String()
		out = append(out, obs{"path": f, "days_left": strconv.Itoa(days), "expired": boolStr(now.After(cert.NotAfter)),
			"not_after": cert.NotAfter.UTC().Format("2006-01-02"), "key_type": kt, "key_bits": strconv.Itoa(bits),
			"sig_alg": cert.SignatureAlgorithm.String(), "self_signed": boolStr(self), "subject": truncate(cert.Subject.CommonName, 120),
			fKey: f, fLoc: f})
	}
	return probeOut{obs: out}
}

// ---- walk -------------------------------------------------------------------

const (
	walkDefaultEntries = 20000
	walkHardEntries    = 200000
)

func (env *evalEnv) probeWalk(p *Probe) probeOut {
	depth := p.MaxDepth
	if depth <= 0 {
		depth = 6
	}
	limit := p.MaxEntries
	if limit <= 0 {
		limit = walkDefaultEntries
	}
	if limit > walkHardEntries {
		limit = walkHardEntries
	}
	prune := map[string]bool{"proc": true, "sys": true}
	for _, n := range p.Prune {
		prune[n] = true
	}
	var out []obs
	for _, root := range env.expand(p.Roots) {
		env.h.Walk(root, depth, limit, func(pth string, d fs.DirEntry) error {
			if d.IsDir() && pth != root && prune[d.Name()] {
				return filepath.SkipDir
			}
			if pth == "/proc" || pth == "/sys" {
				return filepath.SkipDir
			}
			switch p.FileType {
			case "file":
				if !d.Type().IsRegular() {
					return nil
				}
			case "dir":
				if !d.IsDir() {
					return nil
				}
			}
			if len(p.Match) > 0 {
				hit := false
				for _, m := range p.Match {
					if ok, _ := path.Match(m, d.Name()); ok {
						hit = true
						break
					}
				}
				if !hit {
					return nil
				}
			}
			m, err := env.h.Stat(pth)
			if err != nil {
				return nil
			}
			o := obs{"path": pth, "name": d.Name(), fKey: pth, fLoc: pth}
			env.metaObs(o, m)
			out = append(out, o)
			if len(out) >= 5000 {
				return filepath.SkipAll
			}
			return nil
		})
	}
	return probeOut{obs: out}
}

// versionCmp compares two versions with RPM rules (good enough for dpkg
// and apk upstream versions too).
func versionCmp(a, b string) int { return matcher.CompareNEVR(a, b) }
