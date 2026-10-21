package rules

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

func init() {
	register(
		CheckInfo{ID: "php:upload-progress", Rule: "php", Severity: finding.SeverityHigh,
			Description: "session.upload_progress.enabled is On (default) - exposure for CVE-2026-109618 / CVE-2026-109619"},
		CheckInfo{ID: "php:expose-php", Rule: "php", Severity: finding.SeverityLow, Description: "expose_php=On advertises the PHP version"},
		CheckInfo{ID: "php:display-errors", Rule: "php", Severity: finding.SeverityMedium, Description: "display_errors on: errors (paths, SQL) shown to visitors"},
		CheckInfo{ID: "php:allow-url-include", Rule: "php", Severity: finding.SeverityHigh, Description: "allow_url_include=On enables remote file inclusion"},
		CheckInfo{ID: "php:cgi-fix-pathinfo", Rule: "php", Severity: finding.SeverityLow, Description: "cgi.fix_pathinfo=1 (default) with FPM"},
		CheckInfo{ID: "php:disable-functions-empty", Rule: "php", Severity: finding.SeverityLow, Description: "disable_functions is empty (no defense in depth against webshells)"},
		CheckInfo{ID: "php:session-path", Rule: "php", Severity: finding.SeverityMedium, Description: "session.save_path missing or not writable by the pool user"},
		CheckInfo{ID: "php:eol-branch", Rule: "php", Severity: finding.SeverityHigh, Description: "PHP branch past upstream end-of-life (<= 8.1)"},
	)
}

// PHPRule audits effective php.ini settings per installation and FPM pool:
// system PHP (/etc/php.ini + /etc/php.d), Remi SCL (/etc/opt/remi/phpXY),
// and Debian/Ubuntu (/etc/php/X.Y/fpm).
type PHPRule struct{}

func NewPHPRule() *PHPRule { return &PHPRule{} }

func (r *PHPRule) Name() string { return "php" }

// phpInstall is one PHP installation's ini chain and pool directory.
type phpInstall struct {
	Name     string // "system", "remi-php80", "debian-8.1"
	Branch   string // "8.0" if known from the path
	Ini      string
	IniDir   string
	PoolGlob string
	ExtraIni string // where Lync suggests dropping an override
	Service  string
}

type phpPool struct {
	Install  string
	Name     string
	File     string
	User     string
	Listen   string
	Settings map[string]string
}

func phpInstalls(h *Host) []phpInstall {
	var out []phpInstall
	if h.Exists("/etc/php.ini") {
		out = append(out, phpInstall{Name: "system", Ini: "/etc/php.ini", IniDir: "/etc/php.d",
			PoolGlob: "/etc/php-fpm.d/*.conf", ExtraIni: "/etc/php.d/99-lync.ini", Service: "php-fpm"})
	}
	for _, d := range h.Glob("/etc/opt/remi/php*") {
		base := path.Base(d) // php80
		if !h.Exists(d + "/php.ini") {
			continue
		}
		br := ""
		if len(base) == 5 {
			br = base[3:4] + "." + base[4:5]
		}
		out = append(out, phpInstall{Name: "remi-" + base, Branch: br, Ini: d + "/php.ini", IniDir: d + "/php.d",
			PoolGlob: d + "/php-fpm.d/*.conf", ExtraIni: d + "/php.d/99-lync.ini", Service: base + "-php-fpm"})
	}
	for _, d := range h.Glob("/etc/php/*/fpm") {
		ver := path.Base(path.Dir(d))
		if !h.Exists(d + "/php.ini") {
			continue
		}
		out = append(out, phpInstall{Name: "debian-" + ver, Branch: ver, Ini: d + "/php.ini", IniDir: d + "/conf.d",
			PoolGlob: d + "/pool.d/*.conf", ExtraIni: d + "/conf.d/99-lync.ini", Service: "php" + ver + "-fpm"})
	}
	return out
}

// parseINI reads key = value lines (sections ignored, ; comments).
func parseINI(src string, into map[string]string) {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == ';' || line[0] == '#' || line[0] == '[' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if i := strings.Index(v, " ;"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		into[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(v, `"'`)
	}
}

func phpBaseSettings(h *Host, in phpInstall) map[string]string {
	set := map[string]string{}
	if b, err := h.ReadFile(in.Ini); err == nil {
		parseINI(string(b), set)
	}
	for _, f := range h.Glob(in.IniDir + "/*.ini") {
		if b, err := h.ReadFile(f); err == nil {
			parseINI(string(b), set)
		}
	}
	return set
}

var distroBuildRE = regexp.MustCompile(`[.+]el\d`)

var poolValueRE = regexp.MustCompile(`^php_(?:admin_)?(?:value|flag)\[([^\]]+)\]\s*=\s*(.*)$`)

// parsePools splits an FPM pool file into [name] sections.
func parsePools(install, file, src string) []phpPool {
	var pools []phpPool
	var cur *phpPool
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.Trim(line, "[]")
			if name == "global" {
				cur = nil
				continue
			}
			pools = append(pools, phpPool{Install: install, Name: name, File: file, Settings: map[string]string{}})
			cur = &pools[len(pools)-1]
			continue
		}
		if cur == nil {
			continue
		}
		if m := poolValueRE.FindStringSubmatch(line); m != nil {
			cur.Settings[strings.ToLower(m[1])] = strings.Trim(strings.TrimSpace(m[2]), `"'`)
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "user":
			cur.User = strings.TrimSpace(v)
		case "listen":
			cur.Listen = strings.TrimSpace(v)
		}
	}
	return pools
}

func phpPools(h *Host) []phpPool {
	return h.once("php-pools", func() any {
		var out []phpPool
		for _, in := range phpInstalls(h) {
			for _, f := range h.Glob(in.PoolGlob) {
				if b, err := h.ReadFile(f); err == nil {
					out = append(out, parsePools(in.Name, f, string(b))...)
				}
			}
		}
		return out
	}).([]phpPool)
}

func phpOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "on", "yes", "true", "stdout", "stderr":
		return true
	}
	return false
}

// phpEOL is upstream security-support end per branch.
var phpEOL = map[string]string{
	"5.6": "2018-12-31", "7.0": "2019-01-10", "7.1": "2019-12-01", "7.2": "2020-11-30", "7.3": "2021-12-06",
	"7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31", "8.3": "2027-12-31", "8.4": "2028-12-31",
}

// phpBranchFromPackages finds the system PHP branch from installed packages.
func phpBranchFromPackages(facts *collector.Facts) (branch, nevra string) {
	if facts == nil {
		return "", ""
	}
	for _, p := range facts.Packages {
		if p.Name == "php-common" || p.Name == "php-cli" || p.Name == "php-fpm" {
			return streamOfVersion(p.Version), p.NEVRA()
		}
	}
	return "", ""
}

func streamOfVersion(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return v
}

func (r *PHPRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	h := opts.host()
	installs := phpInstalls(h)
	if len(installs) == 0 {
		return nil
	}
	pools := phpPools(h)
	var out []finding.Finding
	now := h.now()
	for _, in := range installs {
		base := phpBaseSettings(h, in)
		type scope struct {
			key  string
			desc string
			set  map[string]string
			pool *phpPool
		}
		var scopes []scope
		for i := range pools {
			if pools[i].Install != in.Name {
				continue
			}
			eff := map[string]string{}
			for k, v := range base {
				eff[k] = v
			}
			for k, v := range pools[i].Settings {
				eff[k] = v
			}
			scopes = append(scopes, scope{in.Name + ":" + pools[i].Name, fmt.Sprintf("%s pool [%s] (%s)", in.Name, pools[i].Name, pools[i].File), eff, &pools[i]})
		}
		if len(scopes) == 0 {
			scopes = append(scopes, scope{in.Name, in.Name + " (" + in.Ini + ")", base, nil})
		}
		restart := "systemctl restart " + in.Service
		for _, sc := range scopes {
			get := func(k, def string) (string, bool) {
				v, ok := sc.set[k]
				if !ok {
					return def, false
				}
				return v, true
			}
			if opts.on("php:upload-progress") {
				v, set := get("session.upload_progress.enabled", "1")
				if phpOn(v) {
					src := "not set (PHP default On)"
					if set {
						src = "= " + v
					}
					out = append(out, mkFinding(h, "php:upload-progress", sc.key, finding.CategoryConfig, finding.SeverityHigh,
						"PHP session.upload_progress.enabled is On ("+sc.desc+")",
						"session.upload_progress.enabled "+src+"; upload-progress session handling is the attack surface of CVE-2026-109618 / CVE-2026-109619 until patched builds are installed",
						fmt.Sprintf("echo 'session.upload_progress.enabled = Off' > %s && %s  (for a pool: php_admin_flag[session.upload_progress.enabled] = off)", in.ExtraIni, restart),
						"https://nvd.nist.gov/vuln/detail/CVE-2026-109618", "https://nvd.nist.gov/vuln/detail/CVE-2026-109619",
						"https://www.php.net/manual/en/session.configuration.php#ini.session.upload-progress.enabled"))
				}
			}
			if opts.on("php:expose-php") {
				if v, _ := get("expose_php", "1"); phpOn(v) {
					out = append(out, mkFinding(h, "php:expose-php", sc.key, finding.CategoryConfig, finding.SeverityLow,
						"PHP expose_php is On ("+sc.desc+")", "expose_php = "+v+" (X-Powered-By header reveals the exact PHP version)",
						fmt.Sprintf("echo 'expose_php = Off' >> %s && %s", in.ExtraIni, restart)))
				}
			}
			if opts.on("php:display-errors") {
				if v, _ := get("display_errors", "1"); phpOn(v) {
					out = append(out, mkFinding(h, "php:display-errors", sc.key, finding.CategoryConfig, finding.SeverityMedium,
						"PHP display_errors is on ("+sc.desc+")", "display_errors = "+v,
						fmt.Sprintf("echo 'display_errors = Off' >> %s && %s  (log errors instead: log_errors = On)", in.ExtraIni, restart)))
				}
			}
			if opts.on("php:allow-url-include") {
				if v, _ := get("allow_url_include", "0"); phpOn(v) {
					out = append(out, mkFinding(h, "php:allow-url-include", sc.key, finding.CategoryConfig, finding.SeverityHigh,
						"PHP allow_url_include is On ("+sc.desc+")", "allow_url_include = "+v+" (include() of remote URLs = remote code execution on any LFI)",
						fmt.Sprintf("echo 'allow_url_include = Off' >> %s && %s", in.ExtraIni, restart)))
				}
			}
			if opts.on("php:cgi-fix-pathinfo") && sc.pool != nil {
				if v, _ := get("cgi.fix_pathinfo", "1"); v == "1" {
					out = append(out, mkFinding(h, "php:cgi-fix-pathinfo", sc.key, finding.CategoryConfig, finding.SeverityLow,
						"PHP cgi.fix_pathinfo=1 under FPM ("+sc.desc+")", "cgi.fix_pathinfo = 1: /upload/image.jpg/x.php can execute image.jpg as PHP unless nginx uses try_files $uri =404",
						fmt.Sprintf("echo 'cgi.fix_pathinfo = 0' >> %s && %s", in.ExtraIni, restart)))
				}
			}
			if opts.on("php:disable-functions-empty") && opts.Level >= LevelMedium {
				if v, _ := get("disable_functions", ""); strings.TrimSpace(v) == "" {
					out = append(out, mkFinding(h, "php:disable-functions-empty", sc.key, finding.CategoryHardening, finding.SeverityLow,
						"PHP disable_functions is empty ("+sc.desc+")", "disable_functions is empty: a webshell can call exec/system/passthru freely",
						fmt.Sprintf("If the apps don't need them: echo 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec' >> %s && %s", in.ExtraIni, restart)))
				}
			}
			if opts.on("php:session-path") && sc.pool != nil && sc.pool.User != "" {
				v, _ := get("session.save_path", "")
				dir := v
				if i := strings.LastIndex(dir, ";"); i >= 0 {
					dir = dir[i+1:]
				}
				if strings.HasPrefix(dir, "/") {
					acct, ok := h.Account(sc.pool.User)
					switch {
					case !h.IsDir(dir):
						out = append(out, mkFinding(h, "php:session-path", sc.key, finding.CategoryConfig, finding.SeverityMedium,
							"PHP session.save_path does not exist ("+sc.desc+")", "session.save_path = "+v+" (directory missing: logins/sessions will fail)",
							fmt.Sprintf("install -d -m 770 -o root -g %s %s", sc.pool.User, dir)))
					case ok && !h.WritableBy(dir, acct):
						out = append(out, mkFinding(h, "php:session-path", sc.key, finding.CategoryConfig, finding.SeverityMedium,
							"PHP session.save_path not writable by pool user "+sc.pool.User+" ("+sc.desc+")", "session.save_path = "+dir,
							fmt.Sprintf("chgrp %s %s && chmod 770 %s", sc.pool.User, dir, dir)))
					}
				}
			}
		}
		if opts.on("php:eol-branch") {
			branch, evidence, distro := in.Branch, in.Ini, false
			if in.Name == "system" {
				var nevra string
				branch, nevra = phpBranchFromPackages(facts)
				evidence, distro = "installed "+nevra, true
			}
			if eol, ok := phpEOL[branch]; ok {
				t, _ := time.Parse("2006-01-02", eol)
				if now.After(t) {
					sev := finding.SeverityHigh
					note := ""
					if distro && distroBuildRE.MatchString(evidence) {
						sev = finding.SeverityMedium
						note = " Distro builds (RHEL/Rocky appstream) may still receive backported fixes until the module stream retires; check `dnf module list php` for the stream's status."
					}
					out = append(out, mkFinding(h, "php:eol-branch", in.Name, finding.CategoryEOL, sev,
						fmt.Sprintf("PHP %s is past upstream end-of-life (%s, %s)", branch, eol, in.Name),
						evidence+"; upstream security support for PHP "+branch+" ended "+eol+"."+note,
						"Move to a supported branch (8.2+): RHEL/Rocky `dnf module switch-to php:8.2`, Remi `dnf install php83-php-fpm`, then migrate pools and test the apps",
						"https://www.php.net/supported-versions.php"))
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
