package rules

import (
	"context"
	"github.com/ryan785/lync/internal/audit"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// SELinuxRule reports SELinux enforcement state on RHEL-family hosts and
// AppArmor state on Debian/Ubuntu hosts. A host running without an MAC
// layer is a significant exposure on a production system.
type SELinuxRule struct{}

func NewSELinuxRule() *SELinuxRule { return &SELinuxRule{} }

func (r *SELinuxRule) Name() string { return "mac" }

func (r *SELinuxRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	switch {
	case rhelFamily(facts.OS):
		return r.scanSELinux(ctx, opts)
	case debianFamily(facts.OS):
		return r.scanAppArmor(ctx, opts)
	}
	return nil
}

func (r *SELinuxRule) scanSELinux(ctx context.Context, opts Options) []finding.Finding {
	mode := getEnforceMode(ctx)
	now := time.Now()
	switch mode {
	case "enforcing":
		return nil
	case "permissive":
		return []finding.Finding{{
			ID:          "mac:selinux-permissive",
			Category:    finding.CategoryConfig,
			Severity:    finding.SeverityHigh,
			Title:       "SELinux in permissive mode (denials logged but not enforced)",
			Evidence:    "getenforce -> Permissive",
			Remediation: "Switch to enforcing: `setenforce 1` and edit /etc/selinux/config to set SELINUX=enforcing",
			DetectedAt:  now,
			Source:      "lync-rules",
		}}
	case "disabled":
		return []finding.Finding{{
			ID:          "mac:selinux-disabled",
			Category:    finding.CategoryConfig,
			Severity:    finding.SeverityHigh,
			Title:       "SELinux is disabled (no mandatory access control)",
			Evidence:    "getenforce -> Disabled",
			Remediation: "Re-enable SELinux: set SELINUX=enforcing in /etc/selinux/config and reboot. Note that re-enabling on a long-running host requires a full filesystem relabel.",
			DetectedAt:  now,
			Source:      "lync-rules",
		}}
	}
	// Unable to determine — silently skip on Strict only, since this might
	// be a container/minimal install where selinux tooling isn't present.
	if opts.Level < LevelStrict {
		return nil
	}
	return []finding.Finding{{
		ID:          "mac:selinux-unknown",
		Category:    finding.CategoryConfig,
		Severity:    finding.SeverityLow,
		Title:       "Unable to determine SELinux state (getenforce not available)",
		Evidence:    "getenforce command not found or returned an unexpected value",
		Remediation: "Install policycoreutils: `dnf install -y policycoreutils`",
		DetectedAt:  now,
		Source:      "lync-rules",
	}}
}

func (r *SELinuxRule) scanAppArmor(ctx context.Context, opts Options) []finding.Finding {
	// /sys/module/apparmor/parameters/enabled is "Y" when AppArmor module
	// is loaded. Whether profiles are loaded/enforcing requires aa-status.
	enabled := false
	if data, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		enabled = strings.TrimSpace(string(data)) == "Y"
	}
	now := time.Now()
	if !enabled {
		return []finding.Finding{{
			ID:          "mac:apparmor-disabled",
			Category:    finding.CategoryConfig,
			Severity:    finding.SeverityHigh,
			Title:       "AppArmor not enabled (no mandatory access control)",
			Evidence:    "/sys/module/apparmor/parameters/enabled is not Y",
			Remediation: "Install apparmor + apparmor-utils, enable in /etc/default/grub (apparmor=1 security=apparmor) and reboot",
			DetectedAt:  now,
			Source:      "lync-rules",
		}}
	}
	out, err := audit.Output(ctx, CommandTimeout, "aa-status", "--enforced")
	if err == nil && opts.Level >= LevelMedium {
		enforcedCount := strings.TrimSpace(string(out))
		if enforcedCount == "0" {
			return []finding.Finding{{
				ID:          "mac:apparmor-no-enforced",
				Category:    finding.CategoryConfig,
				Severity:    finding.SeverityMedium,
				Title:       "AppArmor loaded but no profiles are enforcing",
				Evidence:    "aa-status --enforced reports 0 profiles",
				Remediation: "Enable profiles: `aa-enforce /etc/apparmor.d/*` (review profiles first)",
				DetectedAt:  now,
				Source:      "lync-rules",
			}}
		}
	}
	return nil
}

func getEnforceMode(ctx context.Context) string {
	// /sys/fs/selinux/enforce is "0" or "1" when selinux is enabled.
	// Disabled state means the file isn't present.
	if data, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		switch strings.TrimSpace(string(data)) {
		case "1":
			return "enforcing"
		case "0":
			return "permissive"
		}
	}
	// Fall back to getenforce binary
	if out, err := audit.Output(ctx, CommandTimeout, "getenforce"); err == nil {
		return strings.ToLower(strings.TrimSpace(string(out)))
	}
	// Neither — could be a host without SELinux installed at all
	return "disabled"
}

func rhelFamily(os collector.OSInfo) bool {
	switch os.ID {
	case "rhel", "rocky", "almalinux", "centos", "fedora", "ol", "amzn":
		return true
	}
	for _, l := range os.IDLike {
		if l == "rhel" {
			return true
		}
	}
	return false
}

func debianFamily(os collector.OSInfo) bool {
	if os.ID == "debian" || os.ID == "ubuntu" {
		return true
	}
	for _, l := range os.IDLike {
		if l == "debian" {
			return true
		}
	}
	return false
}
