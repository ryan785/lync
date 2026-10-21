package rules

import (
	"testing"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

func kernelFacts() *collector.Facts {
	return &collector.Facts{
		Kernel: collector.KernelInfo{Release: "6.10.3-1.el9.elrepo.x86_64"},
		Packages: []collector.Package{
			{Name: "kernel-ml", Version: "6.10.3", Release: "1.el9.elrepo", Arch: "x86_64", Manager: "rpm"},
			{Name: "kernel-ml", Version: "6.11.1", Release: "1.el9.elrepo", Arch: "x86_64", Manager: "rpm"},
			{Name: "kernel-core", Version: "5.14.0", Release: "503.14.1.el9_5", Arch: "x86_64", Manager: "rpm"},
			{Name: "dnf-automatic", Version: "4.14.0", Release: "17.el9", Manager: "rpm"},
		},
	}
}

func systemFixture(t *testing.T) *fixtureHost {
	fx := newFixture(t)
	fx.file("/proc/sys/kernel/osrelease", "6.10.3-1.el9.elrepo.x86_64\n").
		file("/proc/uptime", "17280000.12 100.0\n"). // 200 days
		file("/etc/selinux/config", "# comment\nSELINUX=enforcing\nSELINUXTYPE=targeted\n").
		file("/sys/fs/selinux/enforce", "0").
		file("/etc/yum.repos.d/elrepo.repo", "[elrepo]\nenabled=1\n[elrepo-kernel]\nname=x\nenabled=0\n").
		file("/etc/dnf/automatic.conf", "[commands]\napply_updates = no\n").
		cmd("grubby --default-kernel", "/boot/vmlinuz-5.14.0-503.14.1.el9_5.x86_64\n").
		cmd("dnf -C -q list --installed kernel-ml", "Installed Packages\nkernel-ml.x86_64   6.10.3-1.el9.elrepo   @elrepo-kernel\nkernel-ml.x86_64   6.11.1-1.el9.elrepo   @elrepo-kernel\n").
		cmd("systemctl list-units --state=failed --plain --no-legend --no-pager", "pm2-root.service loaded failed failed PM2 process manager\nold-backup.timer loaded failed failed Old\n").
		cmd("systemctl is-enabled pm2-root.service", "enabled\n").
		cmd("systemctl is-enabled old-backup.timer", "disabled\n").
		cmd("systemctl show -p Result -p ExecMainStatus pm2-root.service", "Result=exit-code\nExecMainStatus=203\n").
		cmd("systemctl is-enabled dnf-automatic.timer", "enabled\n").
		cmd("dnf -C -q updateinfo list --security", "RLSA-2024:3501 Important/Sec. nghttp2-libs-1.43.0-5.el9_4.3.x86_64\nRLSA-2026:1200 Moderate/Sec.  curl-7.76.1-31.el9.x86_64\nRLSA-2026:1200 Moderate/Sec.  libcurl-7.76.1-31.el9.x86_64\nRLSA-2025:0042 Low/Sec.       tzdata-2025a-1.el9.noarch\n")
	return fx
}

func TestSystemRule(t *testing.T) {
	fx := systemFixture(t)
	got := runRule(NewSystemRule(), kernelFacts(), fx.opts())
	requireShape(t, got)
	want := map[string]finding.Severity{
		"sys:reboot-required:6.11.1-1.el9.elrepo": finding.SeverityMedium,
		"sys:uptime":                finding.SeverityLow,
		"sys:kernel-repo:kernel-ml": finding.SeverityMedium,
		"sys:boot-kernel-downgrade:5.14.0-503.14.1.el9_5.x86_64": finding.SeverityHigh,
		"mac:selinux-runtime-drift":                              finding.SeverityHigh,
		"systemd:failed-unit:pm2-root.service":                   finding.SeverityMedium,
		"systemd:failed-unit:old-backup.timer":                   finding.SeverityLow,
		"updates:no-auto":                                        finding.SeverityLow, // download-only
		"updates:pending-security":                               finding.SeverityHigh,
	}
	for id, sev := range want {
		f := hasID(got, id)
		if f == nil {
			t.Errorf("missing %s; got %v", id, ids(got))
			continue
		}
		if f.Severity != sev {
			t.Errorf("%s severity %s, want %s", id, f.Severity, sev)
		}
	}
	if f := hasID(got, "updates:pending-security"); f != nil && f.Title != "3 pending security advisories (1 Important, 1 Moderate, 1 Low)" {
		t.Errorf("pending title = %q", f.Title)
	}
	if f := hasID(got, "systemd:failed-unit:pm2-root.service"); f != nil && !contains(f.Evidence, "ExecMainStatus=203") {
		t.Errorf("failed-unit evidence = %q", f.Evidence)
	}
}

func TestSystemRuleHealthy(t *testing.T) {
	fx := newFixture(t)
	fx.file("/proc/sys/kernel/osrelease", "5.14.0-503.14.1.el9_5.x86_64").
		file("/proc/uptime", "86400 1").
		file("/etc/selinux/config", "SELINUX=enforcing\n").
		file("/sys/fs/selinux/enforce", "1").
		file("/etc/yum.repos.d/rocky.repo", "[baseos]\n").
		file("/etc/dnf/automatic.conf", "[commands]\napply_updates = yes\n").
		cmd("grubby --default-kernel", "/boot/vmlinuz-5.14.0-503.14.1.el9_5.x86_64").
		cmd("dnf -C -q list --installed kernel-core", "kernel-core.x86_64 5.14.0-503.14.1.el9_5 @baseos\n").
		cmd("systemctl list-units --state=failed --plain --no-legend --no-pager", "").
		cmd("systemctl is-enabled dnf-automatic.timer", "enabled").
		cmd("dnf -C -q updateinfo list --security", "")
	facts := &collector.Facts{Packages: []collector.Package{
		{Name: "kernel-core", Version: "5.14.0", Release: "503.14.1.el9_5", Manager: "rpm"},
		{Name: "dnf-automatic", Version: "4", Release: "1", Manager: "rpm"},
	}}
	if got := runRule(NewSystemRule(), facts, fx.opts()); len(got) != 0 {
		t.Errorf("healthy host: got %v", ids(got))
	}
}

func TestSystemRuleNoTools(t *testing.T) {
	fx := newFixture(t)
	if got := runRule(NewSystemRule(), &collector.Facts{}, fx.opts()); len(got) != 0 {
		t.Errorf("empty host: got %v", ids(got))
	}
}

func TestAutoUpdatesMissingPackage(t *testing.T) {
	fx := newFixture(t)
	fx.dir("/etc/yum.repos.d")
	got := runRule(NewSystemRule(), &collector.Facts{}, fx.opts())
	if f := hasID(got, "updates:no-auto"); f == nil || f.Severity != finding.SeverityMedium {
		t.Errorf("want medium updates:no-auto, got %v", ids(got))
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
