// Package rules implements non-CVE intelligence checks that produce
// finding.Finding records like the matcher does, but from host
// configuration rather than installed package versions. Each Rule is a
// self-contained check (sshd config, sysctl hardening, filesystem
// permissions, etc.). The Engine runs them all concurrently and returns
// the merged findings list.
package rules

import (
	"context"
	"github.com/ryan785/lync/internal/audit"
	"log/slog"
	"sync"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

type Rule interface {
	Name() string
	Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding
}

type Engine struct {
	rules []Rule
	log   *slog.Logger
	level Level
	opts  Options
}

func NewEngine(log *slog.Logger, level Level, rs ...Rule) *Engine {
	return &Engine{rules: rs, log: log, level: level, opts: Options{Level: level}}
}

// NewEngineWithOptions is NewEngine with host, toggles and tunables.
func NewEngineWithOptions(log *slog.Logger, opts Options, rs ...Rule) *Engine {
	return &Engine{rules: rs, log: log, level: opts.Level, opts: opts}
}

// Run executes all rules concurrently. A panicking rule logs and yields
// no findings rather than taking down the daemon.
func (e *Engine) Run(ctx context.Context, facts *collector.Facts) []finding.Finding {
	if len(e.rules) == 0 {
		return nil
	}
	start := time.Now()
	opts := e.opts
	opts.Level = e.level
	// One Host per scan so memoized lookups (ss, passwd, nginx) are shared
	// by every rule but never go stale between scans.
	opts.Host = opts.Host.Fresh()
	results := make([][]finding.Finding, len(e.rules))
	var wg sync.WaitGroup
	for i, r := range e.rules {
		i, r := i, r
		if !opts.Toggles.RuleEnabled(r.Name()) {
			audit.Log("RULE", "%s skipped (disabled by rules.disable)", r.Name())
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if v := recover(); v != nil {
					e.log.Error("rule panicked", "rule", r.Name(), "panic", v)
				}
			}()
			start := time.Now()
			results[i] = r.Run(ctx, facts, e.log.With("rule", r.Name()), opts)
			audit.Log("RULE", "%s ran findings=%d dur=%s", r.Name(), len(results[i]), time.Since(start).Round(time.Millisecond))
		}()
	}
	wg.Wait()
	var out []finding.Finding
	perCheck := map[string]int{}
	for _, r := range results {
		for _, f := range r {
			// Toggles also apply to checks that don't guard themselves
			// (the original rules), by finding-ID prefix.
			if opts.Toggles.CheckEnabled(f.ID) {
				out = append(out, f)
				catalogMu.Lock()
				perCheck[checkIDOf(f.ID)]++
				catalogMu.Unlock()
			}
		}
	}
	if audit.Enabled() {
		for _, c := range Catalog() {
			state := "on"
			switch {
			case !opts.Toggles.RuleEnabled(c.Rule):
				state = "off(rule disabled)"
			case !opts.Toggles.CheckEnabled(c.ID):
				state = "off"
				if c.DefaultOff {
					state = "off(opt-in)"
				}
			}
			audit.Log("CHECK", "%s state=%s findings=%d", c.ID, state, perCheck[c.ID])
		}
	}
	e.log.Info("rules engine complete",
		"level", e.level.String(),
		"rules", len(e.rules),
		"findings", len(out),
		"duration", time.Since(start))
	return out
}

// DefaultRules returns the rules shipped in-box. Custom rules can be added
// by callers building their own Engine.
func DefaultRules() []Rule {
	return []Rule{
		NewHardeningRule(),
		NewSSHConfigRule(),
		NewAccountRule(),
		NewFilesystemRule(),
		NewNetworkRule(),
		NewEOLRule(),
		NewWebServerRule(),
		NewFirewallRule(),
		NewLoginDefsRule(),
		NewMountRule(),
		NewSELinuxRule(),
		NewWebExposureRule(),
		NewPHPRule(),
		NewExposureRule(),
		NewSystemRule(),
		NewAccessRule(),
		NewRuntimesRule(),
		NewVPNRule(),
	}
}

// Catalog entries for the original rules, by finding-ID prefix, so
// `lync checks` lists them and rules.disable can target them.
func init() {
	register(
		CheckInfo{ID: "hardening", Rule: "hardening", Severity: finding.SeverityMedium, Description: "sysctl kernel/network hardening values"},
		CheckInfo{ID: "ssh", Rule: "ssh-config", Severity: finding.SeverityHigh, Description: "sshd_config settings (root login, passwords, ciphers, MACs, KEX, forwarding...)"},
		CheckInfo{ID: "account:uid0", Rule: "accounts", Severity: finding.SeverityCritical, Description: "Non-root account with UID 0"},
		CheckInfo{ID: "account:empty-pwd", Rule: "accounts", Severity: finding.SeverityCritical, Description: "Account with an empty password hash"},
		CheckInfo{ID: "fs:world-writable", Rule: "filesystem", Severity: finding.SeverityHigh, Description: "World-writable files under /etc, /usr/local, /opt"},
		CheckInfo{ID: "fs:unexpected-setuid", Rule: "filesystem", Severity: finding.SeverityMedium, Description: "Setuid binaries outside the baseline"},
		CheckInfo{ID: "net:exposed", Rule: "network", Severity: finding.SeverityMedium, Description: "TCP service listening on all interfaces (other than 22/80/443)"},
		CheckInfo{ID: "eol", Rule: "eol", Severity: finding.SeverityHigh, Description: "OS release past or near end-of-life (endoflife.date)"},
		CheckInfo{ID: "nginx", Rule: "web-server", Severity: finding.SeverityHigh, Description: "nginx.conf hardening: server_tokens, TLS protocols/ciphers, security headers, autoindex"},
		CheckInfo{ID: "apache", Rule: "web-server", Severity: finding.SeverityHigh, Description: "Apache hardening: ServerTokens/Signature, TLS, TRACE, indexes"},
		CheckInfo{ID: "firewall:none-active", Rule: "firewall", Severity: finding.SeverityHigh, Description: "No active host firewall"},
		CheckInfo{ID: "login-defs", Rule: "login-defs", Severity: finding.SeverityLow, Description: "/etc/login.defs password aging and hashing"},
		CheckInfo{ID: "mount", Rule: "mount", Severity: finding.SeverityLow, Description: "Missing nodev/nosuid/noexec on /tmp, /dev/shm, /var/tmp..."},
		CheckInfo{ID: "mac", Rule: "mac", Severity: finding.SeverityMedium, Description: "SELinux/AppArmor disabled or permissive"},
	)
}
