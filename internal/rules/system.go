package rules

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/matcher"
)

func init() {
	register(
		CheckInfo{ID: "sys:reboot-required", Rule: "system", Severity: finding.SeverityMedium,
			Description: "Running kernel is older than the newest installed kernel (patches not active until reboot)"},
		CheckInfo{ID: "sys:uptime", Rule: "system", Severity: finding.SeverityLow, Description: "Uptime over 180 days"},
		CheckInfo{ID: "sys:kernel-repo", Rule: "system", Severity: finding.SeverityMedium,
			Description: "Running kernel package comes from a disabled or unknown repo (e.g. elrepo kernel-ml with the repo off): no updates"},
		CheckInfo{ID: "sys:boot-kernel-downgrade", Rule: "system", Severity: finding.SeverityHigh,
			Description: "Boot default kernel is older than the running kernel: next reboot silently downgrades"},
		CheckInfo{ID: "mac:selinux-runtime-drift", Rule: "system", Severity: finding.SeverityHigh,
			Description: "SELinux enforcing in /etc/selinux/config but permissive/disabled at runtime (setenforce 0)"},
		CheckInfo{ID: "systemd:failed-unit", Rule: "system", Severity: finding.SeverityMedium,
			Description: "systemd units in failed state (enabled ones rate higher)"},
		CheckInfo{ID: "updates:no-auto", Rule: "system", Severity: finding.SeverityMedium,
			Description: "No automatic security updates (dnf-automatic / unattended-upgrades absent or disabled)"},
		CheckInfo{ID: "updates:pending-security", Rule: "system", Severity: finding.SeverityHigh,
			Description: "Pending security advisories (dnf updateinfo, cache only), by severity with the oldest advisory"},
	)
}

// SystemRule covers kernel/boot state, SELinux drift, unit health and
// update hygiene.
type SystemRule struct{}

func NewSystemRule() *SystemRule { return &SystemRule{} }

func (r *SystemRule) Name() string { return "system" }

func (r *SystemRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	h := opts.host()
	var out []finding.Finding
	running := runningKernel(h, facts)
	if opts.on("sys:reboot-required") && running != "" {
		out = append(out, rebootRequired(h, facts, running)...)
	}
	if opts.on("sys:uptime") {
		if b, err := h.ReadFile("/proc/uptime"); err == nil {
			if f := strings.Fields(string(b)); len(f) > 0 {
				if secs, err := strconv.ParseFloat(f[0], 64); err == nil && secs > 180*86400 {
					out = append(out, mkFinding(h, "sys:uptime", "", finding.CategoryHardening, finding.SeverityLow,
						fmt.Sprintf("Host up for %d days", int(secs/86400)),
						"uptime > 180 days: kernel, glibc and openssl fixes installed since then are not running",
						"Schedule a reboot window; check what needs it with: needs-restarting -r; needs-restarting -s"))
				}
			}
		}
	}
	if opts.on("sys:kernel-repo") && running != "" {
		out = append(out, kernelRepo(ctx, h, facts, running)...)
	}
	if opts.on("sys:boot-kernel-downgrade") && running != "" {
		if def, err := h.Run(ctx, "grubby", "--default-kernel"); err == nil {
			def = strings.TrimSpace(def)
			bootRel := strings.TrimPrefix(def, "/boot/vmlinuz-")
			if bootRel != "" && bootRel != def && bootRel != running && matcher.CompareNEVR(stripArch(bootRel), stripArch(running)) < 0 {
				out = append(out, mkFinding(h, "sys:boot-kernel-downgrade", bootRel, finding.CategoryHardening, finding.SeverityHigh,
					"Next boot will start an older kernel ("+bootRel+")",
					fmt.Sprintf("running %s, grubby --default-kernel = %s", running, def),
					fmt.Sprintf("grubby --set-default /boot/vmlinuz-%s  (verify: grubby --default-kernel)", running)))
			}
		}
	}
	if opts.on("mac:selinux-runtime-drift") {
		out = append(out, selinuxDrift(h)...)
	}
	if opts.on("systemd:failed-unit") {
		out = append(out, failedUnits(ctx, h)...)
	}
	if opts.on("updates:no-auto") {
		out = append(out, autoUpdates(ctx, h, facts)...)
	}
	if opts.on("updates:pending-security") {
		out = append(out, pendingSecurity(ctx, h, facts)...)
	}
	return out
}

func runningKernel(h *Host, facts *collector.Facts) string {
	if b, err := h.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	if facts != nil {
		return facts.Kernel.Release
	}
	return ""
}

var archSuffixRE = regexp.MustCompile(`\.(x86_64|aarch64|ppc64le|s390x|i686|noarch)(\+\w+)?$`)

func stripArch(rel string) string { return archSuffixRE.ReplaceAllString(rel, "") }

var kernelPkgNames = map[string]bool{"kernel": true, "kernel-core": true, "kernel-ml": true, "kernel-ml-core": true,
	"kernel-lt": true, "kernel-lt-core": true, "kernel-uek": true, "kernel-rt-core": true}

// kernelFamily finds the installed package that matches the running
// kernel and returns (package name, all installed kernels of that name).
func kernelFamily(facts *collector.Facts, running string) (string, []collector.Package) {
	if facts == nil {
		return "", nil
	}
	want := stripArch(running)
	name := ""
	for _, p := range facts.Packages {
		if kernelPkgNames[p.Name] && p.Version+"-"+p.Release == want {
			name = p.Name
			break
		}
	}
	if name == "" {
		return "", nil
	}
	var fam []collector.Package
	for _, p := range facts.Packages {
		if p.Name == name {
			fam = append(fam, p)
		}
	}
	return name, fam
}

func rebootRequired(h *Host, facts *collector.Facts, running string) []finding.Finding {
	name, fam := kernelFamily(facts, running)
	newest := ""
	if name != "" {
		for _, p := range fam {
			vr := p.Version + "-" + p.Release
			if newest == "" || matcher.CompareNEVR(vr, newest) > 0 {
				newest = vr
			}
		}
	} else if facts != nil {
		// Debian/Ubuntu: linux-image-<release> package names.
		for _, p := range facts.Packages {
			if rel := strings.TrimPrefix(p.Name, "linux-image-"); rel != p.Name && rel != "" && rel[0] >= '0' && rel[0] <= '9' {
				if newest == "" || matcher.CompareNEVR(rel, newest) > 0 {
					newest = rel
				}
			}
		}
	}
	if newest == "" || matcher.CompareNEVR(newest, stripArch(running)) <= 0 {
		return nil
	}
	return []finding.Finding{mkFinding(h, "sys:reboot-required", newest, finding.CategoryHardening, finding.SeverityMedium,
		"Reboot required: running kernel "+running+" is older than installed "+newest,
		fmt.Sprintf("running %s; newest installed %s %s. Kernel CVE fixes in the newer build are not active.", running, orNone(name), newest),
		"Reboot into the new kernel (check the boot default first: grubby --default-kernel)")}
}

// parseRepos reads [id] / enabled= from yum repo files.
func parseRepos(h *Host) map[string]bool {
	repos := map[string]bool{}
	for _, f := range h.Glob("/etc/yum.repos.d/*.repo") {
		b, err := h.ReadFile(f)
		if err != nil {
			continue
		}
		cur := ""
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				cur = strings.Trim(line, "[]")
				repos[cur] = true // enabled defaults to 1
				continue
			}
			if k, v, ok := strings.Cut(line, "="); ok && cur != "" && strings.TrimSpace(k) == "enabled" {
				repos[cur] = strings.TrimSpace(v) == "1"
			}
		}
	}
	return repos
}

func kernelRepo(ctx context.Context, h *Host, facts *collector.Facts, running string) []finding.Finding {
	name, _ := kernelFamily(facts, running)
	if name == "" {
		return nil
	}
	out, err := h.Run(ctx, "dnf", "-C", "-q", "list", "--installed", name)
	if err != nil && out == "" {
		return nil
	}
	want := stripArch(running)
	repo := ""
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !strings.HasPrefix(f[0], name+".") {
			continue
		}
		vr := f[1]
		if i := strings.IndexByte(vr, ':'); i >= 0 {
			vr = vr[i+1:]
		}
		if vr == want {
			repo = strings.TrimPrefix(f[2], "@")
		}
	}
	if repo == "" {
		return nil
	}
	repos := parseRepos(h)
	enabled, known := repos[repo]
	if known && enabled {
		return nil
	}
	state := "disabled"
	if !known {
		state = "not defined in /etc/yum.repos.d"
	}
	return []finding.Finding{mkFinding(h, "sys:kernel-repo", name, finding.CategoryHardening, finding.SeverityMedium,
		fmt.Sprintf("Running kernel %s comes from repo %q, which is %s", running, repo, state),
		fmt.Sprintf("dnf list --installed %s -> @%s; repo %s. This kernel gets no security updates.", name, repo, state),
		fmt.Sprintf("Either re-enable the repo and keep %s updated (dnf config-manager --set-enabled %s), or boot the distro kernel: grubby --set-default /boot/vmlinuz-<distro kernel> && reboot", name, repo))}
}

func selinuxDrift(h *Host) []finding.Finding {
	b, err := h.ReadFile("/etc/selinux/config")
	if err != nil {
		return nil
	}
	cfg := ""
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k == "SELINUX" {
			cfg = strings.ToLower(strings.TrimSpace(v))
		}
	}
	if cfg != "enforcing" {
		return nil
	}
	runtime := "disabled (no /sys/fs/selinux)"
	if e, err := h.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		if strings.TrimSpace(string(e)) == "1" {
			return nil
		}
		runtime = "permissive (/sys/fs/selinux/enforce = 0)"
	}
	return []finding.Finding{mkFinding(h, "mac:selinux-runtime-drift", "", finding.CategoryHardening, finding.SeverityHigh,
		"SELinux configured enforcing but running "+strings.Fields(runtime)[0],
		"/etc/selinux/config SELINUX=enforcing; runtime "+runtime+". Someone ran setenforce 0 or booted with selinux=0/enforcing=0.",
		"Find the AVC denials that prompted it (ausearch -m avc -ts recent), fix labels/booleans, then setenforce 1 (check kernel cmdline: grubby --info=ALL | grep -E 'selinux|enforcing')")}
}

func failedUnits(ctx context.Context, h *Host) []finding.Finding {
	out, err := h.Run(ctx, "systemctl", "list-units", "--state=failed", "--plain", "--no-legend", "--no-pager")
	if err != nil && out == "" {
		return nil
	}
	var res []finding.Finding
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "●"))
		if len(f) < 1 || !strings.Contains(f[0], ".") {
			continue
		}
		unit := f[0]
		enabled := h.SystemctlIsEnabled(ctx, unit)
		detail := ""
		if show, err := h.Run(ctx, "systemctl", "show", "-p", "Result", "-p", "ExecMainStatus", unit); err == nil || show != "" {
			detail = strings.Join(strings.Fields(show), " ")
		}
		sev := finding.SeverityLow
		if enabled == "enabled" {
			sev = finding.SeverityMedium
		}
		res = append(res, mkFinding(h, "systemd:failed-unit", unit, finding.CategoryRuntime, sev,
			"systemd unit failed: "+unit,
			fmt.Sprintf("%s is failed (is-enabled: %s; %s). An enabled unit that fails at boot often means a security agent, backup or app silently isn't running (e.g. 203/EXEC = binary missing).", unit, orNone(enabled), orNone(detail)),
			fmt.Sprintf("journalctl -b -u %s -n 50; fix and systemctl restart %s, or systemctl disable %s && systemctl reset-failed %s if it's obsolete", unit, unit, unit, unit)))
	}
	return res
}

func autoUpdates(ctx context.Context, h *Host, facts *collector.Facts) []finding.Finding {
	has := func(names ...string) bool {
		if facts == nil {
			return false
		}
		for _, p := range facts.Packages {
			for _, n := range names {
				if p.Name == n {
					return true
				}
			}
		}
		return false
	}
	switch {
	case h.Exists("/etc/yum.repos.d") || h.Exists("/etc/dnf"):
		if !has("dnf-automatic") {
			return []finding.Finding{mkFinding(h, "updates:no-auto", "", finding.CategoryHardening, finding.SeverityMedium,
				"No automatic security updates (dnf-automatic not installed)", "package dnf-automatic is not installed",
				"dnf install -y dnf-automatic && sed -i 's/^upgrade_type.*/upgrade_type = security/; s/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf && systemctl enable --now dnf-automatic.timer")}
		}
		timerOn := false
		for _, t := range []string{"dnf-automatic.timer", "dnf-automatic-install.timer"} {
			if h.SystemctlIsEnabled(ctx, t) == "enabled" {
				timerOn = true
			}
		}
		if !timerOn {
			return []finding.Finding{mkFinding(h, "updates:no-auto", "", finding.CategoryHardening, finding.SeverityMedium,
				"dnf-automatic installed but no timer enabled", "dnf-automatic.timer and dnf-automatic-install.timer are not enabled",
				"systemctl enable --now dnf-automatic.timer (with apply_updates = yes, upgrade_type = security in /etc/dnf/automatic.conf)")}
		}
		if b, err := h.ReadFile("/etc/dnf/automatic.conf"); err == nil {
			set := map[string]string{}
			parseINI(string(b), set)
			if strings.ToLower(set["apply_updates"]) != "yes" && h.SystemctlIsEnabled(ctx, "dnf-automatic-install.timer") != "enabled" {
				return []finding.Finding{mkFinding(h, "updates:no-auto", "", finding.CategoryHardening, finding.SeverityLow,
					"dnf-automatic only downloads updates (apply_updates = no)", "/etc/dnf/automatic.conf apply_updates = "+orNone(set["apply_updates"]),
					"Set apply_updates = yes and upgrade_type = security in /etc/dnf/automatic.conf, or enable dnf-automatic-install.timer")}
			}
		}
	case h.Exists("/etc/apt"):
		if !has("unattended-upgrades") {
			return []finding.Finding{mkFinding(h, "updates:no-auto", "", finding.CategoryHardening, finding.SeverityMedium,
				"No automatic security updates (unattended-upgrades not installed)", "package unattended-upgrades is not installed",
				"apt install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades")}
		}
		on := false
		for _, f := range h.Glob("/etc/apt/apt.conf.d/*") {
			b, _ := h.ReadFile(f)
			if regexp.MustCompile(`APT::Periodic::Unattended-Upgrade\s+"1"`).Match(b) {
				on = true
			}
		}
		if !on {
			return []finding.Finding{mkFinding(h, "updates:no-auto", "", finding.CategoryHardening, finding.SeverityMedium,
				"unattended-upgrades installed but not enabled", `no APT::Periodic::Unattended-Upgrade "1" in /etc/apt/apt.conf.d`,
				"dpkg-reconfigure -plow unattended-upgrades")}
		}
	}
	return nil
}

var advisoryRE = regexp.MustCompile(`^(\S+-(\d{4}):(\d+))\s+(\S+?)/Sec\.`)

func pendingSecurity(ctx context.Context, h *Host, facts *collector.Facts) []finding.Finding {
	out, err := h.Run(ctx, "dnf", "-C", "-q", "updateinfo", "list", "--security")
	if err != nil && out == "" {
		return nil
	}
	bySev := map[string]map[string]bool{}
	oldest, oldestYear, oldestNum := "", 9999, 0
	for _, line := range strings.Split(out, "\n") {
		m := advisoryRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		sev := m[4]
		if bySev[sev] == nil {
			bySev[sev] = map[string]bool{}
		}
		bySev[sev][m[1]] = true
		y, _ := strconv.Atoi(m[2])
		n, _ := strconv.Atoi(m[3])
		if y < oldestYear || y == oldestYear && n < oldestNum {
			oldest, oldestYear, oldestNum = m[1], y, n
		}
	}
	if len(bySev) == 0 {
		return nil
	}
	var parts []string
	total := 0
	for _, s := range []string{"Critical", "Important", "Moderate", "Low", "None"} {
		if n := len(bySev[s]); n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
			total += n
		}
	}
	sev := finding.SeverityLow
	switch {
	case len(bySev["Critical"]) > 0 || len(bySev["Important"]) > 0:
		sev = finding.SeverityHigh
	case len(bySev["Moderate"]) > 0:
		sev = finding.SeverityMedium
	}
	age := ""
	if oldestYear < 9999 {
		age = fmt.Sprintf("; oldest pending advisory %s (issued %d, ~%d year(s) old by advisory ID)", oldest, oldestYear, h.now().Year()-oldestYear)
	}
	return []finding.Finding{mkFinding(h, "updates:pending-security", "", finding.CategoryHardening, sev,
		fmt.Sprintf("%d pending security advisories (%s)", total, strings.Join(parts, ", ")),
		"dnf -C updateinfo list --security (cached metadata, may lag the mirrors)"+age,
		"dnf upgrade --security -y (review with: dnf updateinfo info --security), then reboot if the kernel or glibc changed")}
}
