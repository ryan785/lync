package rules

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// HardeningRule audits sysctl values against a curated set of recommended
// defaults. Each check is tagged with the minimum hardening Level at which
// it fires, so Basic-level operators see only the highest-impact misses
// while Strict-level operators get the CIS-Benchmark-style comprehensive
// list.
type HardeningRule struct{}

func NewHardeningRule() *HardeningRule { return &HardeningRule{} }

func (r *HardeningRule) Name() string { return "hardening" }

type hardeningCheck struct {
	key      string
	want     string
	title    string
	severity finding.Severity
	minLevel Level
}

var hardeningChecks = []hardeningCheck{
	// Critical kernel hardening — Basic level
	{"kernel.randomize_va_space", "2", "ASLR is not fully enabled", finding.SeverityHigh, LevelBasic},
	{"net.ipv4.tcp_syncookies", "1", "TCP SYN cookies disabled (SYN flood mitigation off)", finding.SeverityMedium, LevelBasic},
	{"kernel.kexec_load_disabled", "1", "kernel.kexec_load_disabled is 0 — live-kernel replacement possible", finding.SeverityHigh, LevelBasic},
	{"kernel.unprivileged_bpf_disabled", "1", "Unprivileged eBPF enabled (recent kernel hardening recommendation)", finding.SeverityMedium, LevelBasic},

	// Standard hardening — Medium level (default)
	{"kernel.dmesg_restrict", "1", "kernel.dmesg_restrict is disabled (unprivileged users can read kernel ring buffer)", finding.SeverityMedium, LevelMedium},
	{"kernel.kptr_restrict", "2", "kernel.kptr_restrict is not set to 2 (kernel pointer addresses may leak)", finding.SeverityMedium, LevelMedium},
	{"kernel.yama.ptrace_scope", "1", "kernel.yama.ptrace_scope is 0 (any process can ptrace any other under same uid)", finding.SeverityMedium, LevelMedium},
	{"kernel.perf_event_paranoid", "2", "kernel.perf_event_paranoid below 2 (unprivileged perf access)", finding.SeverityLow, LevelMedium},
	{"kernel.sysrq", "0", "Magic SysRq key enabled (allows console-attached attacker to break out)", finding.SeverityMedium, LevelMedium},
	{"kernel.core_uses_pid", "1", "kernel.core_uses_pid is 0 — core dump filename collisions", finding.SeverityLow, LevelStrict},
	{"net.ipv4.conf.all.rp_filter", "1", "Reverse path filtering disabled on all interfaces (source-spoofed packets accepted)", finding.SeverityMedium, LevelMedium},
	{"net.ipv4.conf.default.rp_filter", "1", "Reverse path filtering default disabled (newly-added interfaces won't filter)", finding.SeverityMedium, LevelMedium},
	{"net.ipv4.conf.all.accept_redirects", "0", "ICMP redirects accepted (kernel will rewrite routes from unauthenticated sources)", finding.SeverityMedium, LevelMedium},
	{"net.ipv4.conf.default.accept_redirects", "0", "ICMP redirects accepted by default on new interfaces", finding.SeverityMedium, LevelMedium},
	{"net.ipv4.conf.all.send_redirects", "0", "ICMP redirects sent from this host (typically only routers should do this)", finding.SeverityLow, LevelMedium},
	{"net.ipv4.conf.default.send_redirects", "0", "ICMP redirects sent by default on new interfaces", finding.SeverityLow, LevelMedium},
	{"net.ipv4.conf.all.accept_source_route", "0", "IPv4 source routing accepted (attacker can dictate path)", finding.SeverityMedium, LevelMedium},
	{"net.ipv4.conf.default.accept_source_route", "0", "IPv4 source routing accepted by default on new interfaces", finding.SeverityMedium, LevelMedium},
	{"net.ipv4.conf.all.log_martians", "1", "Packets with impossible addresses not logged", finding.SeverityLow, LevelMedium},
	{"net.ipv4.icmp_echo_ignore_broadcasts", "1", "Host responds to broadcast pings (smurf-attack amplifier)", finding.SeverityMedium, LevelMedium},
	{"net.ipv4.icmp_ignore_bogus_error_responses", "1", "Bogus ICMP error responses not ignored (log noise risk)", finding.SeverityLow, LevelMedium},
	{"net.ipv4.tcp_max_syn_backlog", "4096", "TCP SYN backlog small enough to DoS easily", finding.SeverityLow, LevelStrict},
	{"net.ipv4.tcp_rfc1337", "1", "RFC 1337 TIME-WAIT assassination protection disabled", finding.SeverityLow, LevelStrict},
	{"net.ipv6.conf.all.accept_redirects", "0", "IPv6 ICMP redirects accepted", finding.SeverityMedium, LevelMedium},
	{"net.ipv6.conf.default.accept_redirects", "0", "IPv6 ICMP redirects accepted by default", finding.SeverityMedium, LevelMedium},
	{"net.ipv6.conf.all.accept_source_route", "0", "IPv6 source routing accepted", finding.SeverityMedium, LevelMedium},
	{"net.ipv6.conf.default.accept_source_route", "0", "IPv6 source routing accepted by default", finding.SeverityMedium, LevelMedium},

	// Filesystem hardening
	{"fs.protected_hardlinks", "1", "fs.protected_hardlinks disabled (symlink/hardlink TOCTOU exposures)", finding.SeverityMedium, LevelMedium},
	{"fs.protected_symlinks", "1", "fs.protected_symlinks disabled", finding.SeverityMedium, LevelMedium},
	{"fs.protected_fifos", "1", "fs.protected_fifos disabled (FIFO race-condition exposure)", finding.SeverityLow, LevelMedium},
	{"fs.protected_regular", "2", "fs.protected_regular not set to 2 (regular-file race-condition exposure)", finding.SeverityLow, LevelMedium},
	{"fs.suid_dumpable", "0", "fs.suid_dumpable nonzero (setuid binaries can produce core dumps)", finding.SeverityLow, LevelMedium},

	// Strict-only — comprehensive but produce noise on benign systems
	{"kernel.modules_disabled", "1", "Kernel modules can still be loaded (Strict-only: locks out hot-loaded modules)", finding.SeverityLow, LevelStrict},
	{"net.ipv4.conf.all.secure_redirects", "0", "Secure ICMP redirects still accepted", finding.SeverityLow, LevelStrict},
	{"net.ipv4.conf.default.secure_redirects", "0", "Secure ICMP redirects accepted by default", finding.SeverityLow, LevelStrict},
	{"net.ipv6.conf.all.forwarding", "0", "IPv6 forwarding enabled (host is acting as a router)", finding.SeverityLow, LevelStrict},
	{"net.ipv4.ip_forward", "0", "IPv4 forwarding enabled (host is acting as a router)", finding.SeverityLow, LevelStrict},
}

func (r *HardeningRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	var out []finding.Finding
	now := time.Now()
	for _, c := range hardeningChecks {
		if c.minLevel > opts.Level {
			continue
		}
		path := "/proc/sys/" + strings.ReplaceAll(c.key, ".", "/")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		got := strings.TrimSpace(string(data))
		if got == c.want {
			continue
		}
		out = append(out, finding.Finding{
			ID:          "hardening:" + c.key,
			Category:    finding.CategoryHardening,
			Severity:    c.severity,
			Title:       c.title,
			Evidence:    fmt.Sprintf("%s = %s (recommended: %s)", c.key, got, c.want),
			Remediation: fmt.Sprintf("echo '%s = %s' >> /etc/sysctl.d/99-lync-hardening.conf && sysctl -p", c.key, c.want),
			DetectedAt:  now,
			Source:      "lync-rules",
		})
	}
	log.Debug("hardening rule scanned",
		"level", opts.Level.String(),
		"checks", len(hardeningChecks),
		"findings", len(out))
	return out
}
