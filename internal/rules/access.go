package rules

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

func init() {
	register(
		CheckInfo{ID: "account:sudo-nopasswd", Rule: "access", Severity: finding.SeverityMedium,
			Description: "sudoers grants NOPASSWD (ALL = High)"},
		CheckInfo{ID: "account:ssh-perms", Rule: "access", Severity: finding.SeverityHigh,
			Description: "~/.ssh or authorized_keys writable by group/others or owned by another user"},
		CheckInfo{ID: "docker:group-members", Rule: "access", Severity: finding.SeverityMedium,
			Description: "Users in the docker group (root-equivalent)"},
		CheckInfo{ID: "docker:socket-perms", Rule: "access", Severity: finding.SeverityCritical,
			Description: "docker.sock writable by non-root users outside the docker group"},
		CheckInfo{ID: "secrets:world-readable", Rule: "access", Severity: finding.SeverityHigh,
			Description: "Password/token-like keys in world-readable systemd units, compose files or .env files (key names only)"},
		CheckInfo{ID: "fs:world-writable-dir", Rule: "access", Severity: finding.SeverityHigh,
			Description: "World-writable directory (no sticky bit) under /etc, web roots or cron dirs"},
		CheckInfo{ID: "cron:writable-script", Rule: "access", Severity: finding.SeverityCritical,
			Description: "Root cron job runs a script that non-root users can modify"},
	)
}

// AccessRule covers privilege paths: sudo, ssh key files, docker, secrets
// readable by everyone, writable dirs and cron scripts.
type AccessRule struct{}

func NewAccessRule() *AccessRule { return &AccessRule{} }

func (r *AccessRule) Name() string { return "access" }

func (r *AccessRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	h := opts.host()
	var out []finding.Finding
	if opts.on("account:sudo-nopasswd") {
		out = append(out, sudoNopasswd(h)...)
	}
	if opts.on("account:ssh-perms") {
		out = append(out, sshPerms(h)...)
	}
	if opts.on("docker:group-members") || opts.on("docker:socket-perms") {
		out = append(out, dockerAccess(h, opts)...)
	}
	if opts.on("secrets:world-readable") {
		out = append(out, worldReadableSecrets(h, opts.SecretScanDirs)...)
	}
	if opts.on("fs:world-writable-dir") {
		roots := append([]string{"/etc", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/var/spool/cron"}, h.webRoots(ctx)...)
		out = append(out, worldWritableDirs(h, roots)...)
	}
	if opts.on("cron:writable-script") {
		out = append(out, cronWritableScripts(h)...)
	}
	return out
}

func sudoNopasswd(h *Host) []finding.Finding {
	files := append([]string{"/etc/sudoers"}, h.Glob("/etc/sudoers.d/*")...)
	var out []finding.Finding
	for _, f := range files {
		b, err := h.ReadFile(f)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") {
				continue
			}
			if !strings.Contains(line, "NOPASSWD") {
				continue
			}
			who := strings.Fields(line)[0]
			cmds := line[strings.Index(line, "NOPASSWD")+len("NOPASSWD"):]
			cmds = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(cmds), ":"))
			sev := finding.SeverityMedium
			if cmds == "ALL" || strings.HasPrefix(cmds, "ALL") {
				sev = finding.SeverityHigh
			}
			out = append(out, mkFinding(h, "account:sudo-nopasswd", fmt.Sprintf("%s:%d", f, i+1), finding.CategoryConfig, sev,
				fmt.Sprintf("Passwordless sudo for %s (%s)", who, cmds),
				fmt.Sprintf("%s:%d: %s", f, i+1, line),
				fmt.Sprintf("visudo -f %s: drop NOPASSWD or limit it to specific commands; a compromised %s session becomes root without a password", f, who)))
		}
	}
	return out
}

func sshPerms(h *Host) []finding.Finding {
	var out []finding.Finding
	for _, a := range h.Accounts() {
		if a.Home == "" || a.Home == "/" || (a.UID != 0 && a.UID < 1000) || strings.HasSuffix(a.Shell, "nologin") || strings.HasSuffix(a.Shell, "false") {
			continue
		}
		for _, p := range []string{a.Home + "/.ssh", a.Home + "/.ssh/authorized_keys", a.Home + "/.ssh/authorized_keys2"} {
			m, err := h.Stat(p)
			if err != nil {
				continue
			}
			problem := ""
			switch {
			case m.Mode.Perm()&0o022 != 0:
				problem = fmt.Sprintf("mode %s is group/other writable", m.Mode.Perm())
			case m.HasOwner && m.UID != a.UID && m.UID != 0:
				problem = fmt.Sprintf("owned by uid %d, not %s (uid %d)", m.UID, a.Name, a.UID)
			}
			if problem == "" {
				continue
			}
			out = append(out, mkFinding(h, "account:ssh-perms", p, finding.CategoryFilesystem, finding.SeverityHigh,
				"Unsafe permissions on "+p, problem+": another user can add a key and log in as "+a.Name+" (sshd StrictModes may also reject the keys)",
				fmt.Sprintf("chown -R %s: %s/.ssh && chmod 700 %s/.ssh && chmod 600 %s/.ssh/authorized_keys", a.Name, a.Home, a.Home, a.Home)))
		}
	}
	return out
}

func dockerAccess(h *Host, opts Options) []finding.Finding {
	var out []finding.Finding
	dockerGID := -1
	for _, g := range h.Groups() {
		if g.Name != "docker" {
			continue
		}
		dockerGID = g.GID
		if opts.on("docker:group-members") && len(g.Members) > 0 {
			out = append(out, mkFinding(h, "docker:group-members", "", finding.CategoryConfig, finding.SeverityMedium,
				"Users in the docker group (root-equivalent): "+strings.Join(g.Members, ", "),
				"docker group members can run `docker run -v /:/host --privileged` and become root without sudo or a password",
				"Remove users who don't need it: gpasswd -d <user> docker (use sudo docker, or rootless Docker/Podman instead)",
				"https://docs.docker.com/engine/security/#docker-daemon-attack-surface"))
		}
	}
	if !opts.on("docker:socket-perms") {
		return out
	}
	for _, sock := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
		m, err := h.Stat(sock)
		if err != nil {
			continue
		}
		perm := m.Mode.Perm()
		bad := ""
		switch {
		case perm&0o002 != 0:
			bad = fmt.Sprintf("mode %s: world-writable", perm)
		case m.HasOwner && perm&0o020 != 0 && m.GID != 0 && m.GID != dockerGID:
			bad = fmt.Sprintf("group-writable by gid %d (not root/docker)", m.GID)
		}
		if bad != "" {
			out = append(out, mkFinding(h, "docker:socket-perms", sock, finding.CategoryConfig, finding.SeverityCritical,
				"Docker socket writable by non-root users: "+sock, bad+" - any local user can take over the host through the Docker API",
				"chown root:docker "+sock+" && chmod 660 "+sock+" (and remove any systemd drop-in / script that chmods it)"))
		}
		break
	}
	return out
}

var (
	secretKeyRE  = regexp.MustCompile(`(?i)(?:^|[\s"'])(?:Environment=)?["']?([A-Z0-9_.-]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)[A-Z0-9_.-]*)["']?\s*[=:]\s*["']?([^\s"'#]+)`)
	secretFlagRE = regexp.MustCompile(`(?i)--(token|password|passwd|secret|api-?key|auth-?key)[= ]+["']?([^\s"']+)`)
)

// secretKeys returns the names of keys that carry a literal value
// (variable references like ${X} or $X are not secrets themselves).
func secretKeys(src string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(k, v string) {
		if v == "" || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "<") || strings.EqualFold(v, "changeme") ||
			strings.EqualFold(v, "null") || strings.EqualFold(v, "none") || strings.HasPrefix(v, "/run/secrets") {
			return
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		for _, m := range secretKeyRE.FindAllStringSubmatch(line, -1) {
			add(m[1], m[2])
		}
		for _, m := range secretFlagRE.FindAllStringSubmatch(line, -1) {
			add("--"+strings.ToLower(m[1]), m[2])
		}
	}
	sort.Strings(out)
	return out
}

var composeNames = map[string]bool{"docker-compose.yml": true, "docker-compose.yaml": true, "compose.yml": true, "compose.yaml": true, ".env": true}

func worldReadableSecrets(h *Host, extra []string) []finding.Finding {
	var files []string
	for _, g := range []string{"/etc/systemd/system/*.service", "/etc/systemd/system/*.service.d/*.conf", "/etc/default/*", "/etc/sysconfig/*"} {
		files = append(files, h.Glob(g)...)
	}
	dirs := append([]string{"/opt", "/srv", "/root", "/home", "/var/www", "/etc/docker"}, extra...)
	for _, d := range dirs {
		h.Walk(d, 4, 30000, func(p string, de fs.DirEntry) error {
			if de.IsDir() && (de.Name() == "node_modules" || de.Name() == ".git" || de.Name() == "vendor") {
				return filepath.SkipDir
			}
			n := de.Name()
			if !de.IsDir() && de.Type().IsRegular() && (composeNames[n] || strings.HasSuffix(n, ".env") || strings.HasPrefix(n, ".env.")) {
				files = append(files, p)
			}
			return nil
		})
	}
	var out []finding.Finding
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		isUnit := strings.HasPrefix(f, "/etc/systemd/system/")
		// Unit Environment= values are exposed by `systemctl show` to every
		// user regardless of file mode, so units are checked unconditionally.
		if !isUnit && !h.WorldReachable(f) {
			continue
		}
		b, err := h.ReadFileLimit(f, 512*1024)
		if err != nil {
			continue
		}
		keys := secretKeys(string(b))
		if len(keys) == 0 {
			continue
		}
		why := "file is world-readable"
		fix := fmt.Sprintf("chmod 600 %s (owner root or the service user); rotate the exposed credentials", f)
		if isUnit {
			why = "systemd unit (Environment=/ExecStart args are readable by any user via `systemctl show` and /proc/<pid>/cmdline)"
			fix = "Move secrets to an EnvironmentFile=/etc/<app>/secrets.env with chmod 600 or use LoadCredential=; don't pass tokens as command-line flags; rotate them"
		}
		out = append(out, mkFinding(h, "secrets:world-readable", f, finding.CategoryFilesystem, finding.SeverityHigh,
			"Secrets readable by any local user: "+f,
			why+"; keys with literal values: "+strings.Join(keys, ", ")+" (values not shown)",
			fix))
	}
	return out
}

func worldWritableDirs(h *Host, roots []string) []finding.Finding {
	var out []finding.Finding
	seen := map[string]bool{}
	for _, root := range roots {
		h.Walk(root, 6, 40000, func(p string, d fs.DirEntry) error {
			if !d.IsDir() || seen[p] {
				return nil
			}
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			seen[p] = true
			m, err := h.Stat(p)
			if err != nil || m.Mode&fs.ModeSymlink != 0 {
				return nil
			}
			if m.Mode.Perm()&0o002 != 0 && m.Mode&fs.ModeSticky == 0 {
				out = append(out, mkFinding(h, "fs:world-writable-dir", p, finding.CategoryFilesystem, finding.SeverityHigh,
					"World-writable directory: "+p, fmt.Sprintf("mode %s without sticky bit under %s: any user can add or replace files", m.Mode.Perm(), root),
					"chmod o-w "+p))
				return filepath.SkipDir
			}
			return nil
		})
	}
	return out
}

// cronCommandPaths extracts absolute paths executed by root cron entries.
func cronCommandPaths(h *Host) map[string]string {
	cmds := map[string]string{} // path -> source line
	addLine := func(src, cmd string) {
		for _, tok := range strings.Fields(cmd) {
			tok = strings.Trim(tok, `"';&|()`)
			if strings.HasPrefix(tok, "/") && !strings.HasPrefix(tok, "/dev/") && !strings.HasPrefix(tok, "/proc/") {
				if _, ok := cmds[tok]; !ok {
					cmds[tok] = src
				}
			}
		}
	}
	parse := func(f string, hasUser bool) {
		b, err := h.ReadFile(f)
		if err != nil {
			return
		}
		for i, line := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || t[0] == '#' || strings.Contains(strings.SplitN(t, " ", 2)[0], "=") {
				continue
			}
			fields := strings.Fields(t)
			skip := 5
			if strings.HasPrefix(fields[0], "@") {
				skip = 1
			}
			if hasUser {
				if len(fields) <= skip || fields[skip] != "root" {
					continue
				}
				skip++
			}
			if len(fields) <= skip {
				continue
			}
			addLine(fmt.Sprintf("%s:%d", f, i+1), strings.Join(fields[skip:], " "))
		}
	}
	parse("/etc/crontab", true)
	for _, f := range h.Glob("/etc/cron.d/*") {
		parse(f, true)
	}
	parse("/var/spool/cron/root", false)
	parse("/var/spool/cron/crontabs/root", false)
	for _, d := range []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		for _, f := range h.Glob(d + "/*") {
			cmds[f] = d
		}
	}
	return cmds
}

func cronWritableScripts(h *Host) []finding.Finding {
	var out []finding.Finding
	cmds := cronCommandPaths(h)
	paths := make([]string, 0, len(cmds))
	for p := range cmds {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		m, err := h.Stat(p)
		if err != nil || m.Mode.IsDir() {
			continue
		}
		problem := ""
		switch {
		case m.Mode.Perm()&0o002 != 0:
			problem = fmt.Sprintf("script mode %s is world-writable", m.Mode.Perm())
		case m.HasOwner && m.UID != 0 && m.Mode.Perm()&0o200 != 0:
			problem = fmt.Sprintf("script owned by uid %d (non-root) and owner-writable", m.UID)
		default:
			if dm, err := h.Stat(path.Dir(p)); err == nil && dm.Mode.Perm()&0o002 != 0 && dm.Mode&fs.ModeSticky == 0 {
				problem = "parent directory " + path.Dir(p) + " is world-writable (script can be replaced)"
			}
		}
		if problem == "" {
			continue
		}
		out = append(out, mkFinding(h, "cron:writable-script", p, finding.CategoryFilesystem, finding.SeverityCritical,
			"Root cron runs a script others can modify: "+p,
			problem+"; referenced by "+cmds[p],
			fmt.Sprintf("chown root:root %s && chmod 755 %s (and chmod o-w %s)", p, p, path.Dir(p))))
	}
	return out
}
