package rules

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// SSHConfigRule parses /etc/ssh/sshd_config and flags risky settings.
// Follows Include (first match wins, like sshd) and stops at the first
// Match block (settings inside a
// Match are conditional and need block-aware parsing — Phase 4 work).
type SSHConfigRule struct {
	path string
}

func NewSSHConfigRule() *SSHConfigRule {
	return &SSHConfigRule{path: "/etc/ssh/sshd_config"}
}

func (r *SSHConfigRule) Name() string { return "ssh-config" }

func (r *SSHConfigRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	cfg, err := parseSSHDConfig(r.path)
	if err != nil {
		log.Debug("ssh_config unreadable", "path", r.path, "err", err)
		return nil
	}
	var out []finding.Finding
	now := time.Now()
	mk := func(minLevel Level, id, title, evidence string, sev finding.Severity, fix string) {
		if minLevel > opts.Level {
			return
		}
		out = append(out, finding.Finding{
			ID:          "ssh:" + id,
			Category:    finding.CategoryConfig,
			Severity:    sev,
			Title:       title,
			Evidence:    evidence,
			Remediation: fix,
			DetectedAt:  now,
			Source:      "lync-rules",
		})
	}

	// --- Basic level — high-impact, almost-no-false-positive ---
	if v := cfg.get("PermitRootLogin"); v == "yes" {
		mk(LevelBasic, "permit-root-login", "SSH allows direct root login",
			"PermitRootLogin yes", finding.SeverityHigh,
			"set PermitRootLogin no (or prohibit-password) in sshd_config and reload sshd")
	}
	if v := cfg.get("PermitEmptyPasswords"); v == "yes" {
		mk(LevelBasic, "empty-passwords", "SSH allows empty passwords",
			"PermitEmptyPasswords yes", finding.SeverityCritical,
			"set PermitEmptyPasswords no")
	}
	if v := cfg.get("Protocol"); v != "" && v != "2" {
		mk(LevelBasic, "protocol-1", "SSH Protocol 1 enabled (deprecated, vulnerable)",
			"Protocol "+v, finding.SeverityCritical,
			"set Protocol 2 only in sshd_config")
	}
	if v := cfg.get("HostbasedAuthentication"); v == "yes" {
		mk(LevelBasic, "host-based-auth", "SSH HostbasedAuthentication enabled (relies on .rhosts-style trust)",
			"HostbasedAuthentication yes", finding.SeverityHigh,
			"set HostbasedAuthentication no")
	}
	if v := cfg.get("IgnoreRhosts"); v == "no" {
		mk(LevelBasic, "ignore-rhosts", "SSH IgnoreRhosts disabled (.rhosts trust relationships honored)",
			"IgnoreRhosts no", finding.SeverityHigh,
			"set IgnoreRhosts yes")
	}

	// --- Medium level — standard hardening ---
	if v := cfg.get("PasswordAuthentication"); v == "yes" {
		mk(LevelMedium, "password-auth", "SSH allows password authentication",
			"PasswordAuthentication yes", finding.SeverityMedium,
			"set PasswordAuthentication no in sshd_config; use SSH keys only")
	}
	if v := cfg.get("ChallengeResponseAuthentication"); v == "yes" {
		mk(LevelMedium, "challenge-response", "SSH ChallengeResponseAuthentication enabled",
			"ChallengeResponseAuthentication yes", finding.SeverityLow,
			"set ChallengeResponseAuthentication no (only relevant if password auth is also disabled)")
	}
	if v := cfg.get("MaxAuthTries"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 4 {
			mk(LevelMedium, "max-auth-tries", fmt.Sprintf("SSH MaxAuthTries permissive: %d", n),
				"MaxAuthTries "+v, finding.SeverityMedium,
				"set MaxAuthTries 4 (or lower) to make brute-force attempts costly")
		}
	}
	if v := cfg.get("LoginGraceTime"); v != "" {
		if secs := parseTimeSeconds(v); secs > 60 {
			mk(LevelMedium, "login-grace-time", fmt.Sprintf("SSH LoginGraceTime is high: %s", v),
				"LoginGraceTime "+v, finding.SeverityLow,
				"set LoginGraceTime 60 (or lower) so half-open connections release faster")
		}
	}
	if v := cfg.get("ClientAliveInterval"); v == "0" || v == "" {
		mk(LevelMedium, "client-alive-interval", "SSH ClientAliveInterval unset — idle sessions never time out",
			"ClientAliveInterval "+orNone(v), finding.SeverityLow,
			"set ClientAliveInterval 300 and ClientAliveCountMax 0 to disconnect idle sessions after 5 minutes")
	}
	if v := cfg.get("X11Forwarding"); v == "yes" {
		mk(LevelMedium, "x11-forwarding", "SSH X11Forwarding enabled",
			"X11Forwarding yes", finding.SeverityLow,
			"set X11Forwarding no unless required")
	}
	if v := cfg.get("LogLevel"); v != "" && !equalsAnyFold(v, "VERBOSE", "INFO") {
		mk(LevelMedium, "log-level", "SSH LogLevel below VERBOSE — login fingerprint not logged",
			"LogLevel "+v, finding.SeverityLow,
			"set LogLevel VERBOSE to record public-key fingerprints alongside session logs")
	}
	if cfg.get("LogLevel") == "" {
		mk(LevelMedium, "log-level-default", "SSH LogLevel not explicitly set (default is INFO; VERBOSE recommended)",
			"LogLevel not set", finding.SeverityLow,
			"set LogLevel VERBOSE in sshd_config")
	}
	if v := cfg.get("AllowAgentForwarding"); v == "yes" {
		mk(LevelMedium, "agent-forwarding", "SSH AllowAgentForwarding enabled (compromised remote can hijack agent)",
			"AllowAgentForwarding yes", finding.SeverityLow,
			"set AllowAgentForwarding no on servers that don't need to act as jump hosts")
	}

	// Weak crypto — Medium level
	weakCipher := map[string]bool{
		"3des-cbc": true, "aes128-cbc": true, "aes192-cbc": true, "aes256-cbc": true,
		"arcfour": true, "arcfour128": true, "arcfour256": true,
		"blowfish-cbc": true, "cast128-cbc": true,
	}
	if v := cfg.get("Ciphers"); v != "" {
		for _, c := range strings.Split(v, ",") {
			c = strings.TrimSpace(c)
			if weakCipher[c] {
				mk(LevelMedium, "weak-cipher-"+c, "SSH advertises weak cipher: "+c,
					"Ciphers "+v, finding.SeverityMedium,
					"remove "+c+" from sshd_config Ciphers; restart sshd")
			}
		}
	}
	weakMAC := map[string]bool{
		"hmac-md5": true, "hmac-md5-96": true, "hmac-sha1-96": true,
		"hmac-md5-etm@openssh.com": true,
	}
	if v := cfg.get("MACs"); v != "" {
		for _, m := range strings.Split(v, ",") {
			m = strings.TrimSpace(m)
			if weakMAC[m] {
				mk(LevelMedium, "weak-mac-"+m, "SSH advertises weak MAC: "+m,
					"MACs "+v, finding.SeverityMedium,
					"remove "+m+" from sshd_config MACs; restart sshd")
			}
		}
	}
	weakKex := map[string]bool{
		"diffie-hellman-group1-sha1":         true,
		"diffie-hellman-group14-sha1":        true,
		"diffie-hellman-group-exchange-sha1": true,
	}
	if v := cfg.get("KexAlgorithms"); v != "" {
		for _, k := range strings.Split(v, ",") {
			k = strings.TrimSpace(k)
			if weakKex[k] {
				mk(LevelMedium, "weak-kex-"+k, "SSH advertises weak key-exchange: "+k,
					"KexAlgorithms "+v, finding.SeverityMedium,
					"remove "+k+" from sshd_config KexAlgorithms; restart sshd")
			}
		}
	}

	// --- Strict level — comprehensive ---
	if cfg.get("Banner") == "" || equalsAnyFold(cfg.get("Banner"), "none") {
		mk(LevelStrict, "no-banner", "SSH has no warning Banner configured",
			"Banner not set", finding.SeverityLow,
			"set Banner /etc/issue.net and populate /etc/issue.net with your acceptable-use policy")
	}
	if v := cfg.get("MaxSessions"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 4 {
			mk(LevelStrict, "max-sessions", fmt.Sprintf("SSH MaxSessions high: %d (per-connection multiplexing limit)", n),
				"MaxSessions "+v, finding.SeverityLow,
				"set MaxSessions 4 unless a specific use-case requires more")
		}
	}
	if v := cfg.get("TCPKeepAlive"); v == "yes" {
		mk(LevelStrict, "tcp-keepalive", "SSH TCPKeepAlive enabled (clients can keep connections via OS keepalive without ClientAlive checks)",
			"TCPKeepAlive yes", finding.SeverityLow,
			"set TCPKeepAlive no; rely on ClientAliveInterval/CountMax for liveness")
	}
	if v := cfg.get("GSSAPIAuthentication"); v == "yes" {
		mk(LevelStrict, "gssapi-auth", "SSH GSSAPIAuthentication enabled",
			"GSSAPIAuthentication yes", finding.SeverityLow,
			"set GSSAPIAuthentication no unless Kerberos is in use")
	}
	if v := cfg.get("KerberosAuthentication"); v == "yes" {
		mk(LevelStrict, "kerberos-auth", "SSH KerberosAuthentication enabled",
			"KerberosAuthentication yes", finding.SeverityLow,
			"set KerberosAuthentication no unless Kerberos is in use")
	}

	// Compound: root may log in with a password. PasswordAuthentication
	// defaults to yes when unset. Without fail2ban/sshguard there is no
	// brake on brute force at all.
	if opts.on("ssh:root-password-login") && strings.EqualFold(cfg.get("PermitRootLogin"), "yes") &&
		(cfg.get("PasswordAuthentication") == "" || strings.EqualFold(cfg.get("PasswordAuthentication"), "yes")) {
		guard := bruteForceGuard(facts)
		sev := finding.SeverityCritical
		ev := "PermitRootLogin yes + PasswordAuthentication " + orNone(cfg.get("PasswordAuthentication")) + " (effective: yes); no fail2ban/sshguard installed"
		if guard != "" {
			sev = finding.SeverityHigh
			ev = "PermitRootLogin yes + password authentication; brute-force protection present: " + guard
		}
		out = append(out, mkFinding(opts.host(), "ssh:root-password-login", "", finding.CategoryConfig, sev,
			"Root can log in over SSH with a password", ev,
			"Put keys in /root/.ssh/authorized_keys, then add `PermitRootLogin prohibit-password` and `PasswordAuthentication no` to the FIRST file sshd reads (e.g. /etc/ssh/sshd_config.d/00-lync.conf), sshd -t && systemctl reload sshd; install fail2ban (dnf install fail2ban; enable the sshd jail)",
			"https://man.openbsd.org/sshd_config#PermitRootLogin"))
	}

	log.Debug("ssh-config rule scanned", "level", opts.Level.String(), "findings", len(out))
	return out
}

type sshdConfig struct {
	values map[string][]string
}

// get returns the first value set for key (case-insensitive), or "" if
// unset. sshd uses FIRST-match semantics: "for each keyword, the first
// obtained value will be used" (sshd_config(5)). That is why RHEL/Rocky put
// `Include /etc/ssh/sshd_config.d/*.conf` at the top of sshd_config.
func (c *sshdConfig) get(key string) string {
	v := c.values[strings.ToLower(key)]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// parseSSHDConfig reads sshd_config, expanding Include directives (globs,
// relative to the config's directory) in place, and stops at the first
// Match block (directives inside are conditional).
func parseSSHDConfig(path string) (*sshdConfig, error) {
	cfg := &sshdConfig{values: map[string][]string{}}
	base := filepath.Dir(path)
	stopped := false
	var load func(p string, depth int) error
	load = func(p string, depth int) error {
		if depth > 5 || stopped {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(strings.ToLower(line), "match ") {
				stopped = true
				return nil
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			key := strings.ToLower(fields[0])
			if key == "include" {
				for _, pat := range fields[1:] {
					if !filepath.IsAbs(pat) && !strings.HasPrefix(pat, "/") {
						pat = filepath.Join(base, pat)
					} else if strings.HasPrefix(pat, "/etc/ssh/") {
						// keep fixture-relative for tests rooted elsewhere
						pat = filepath.Join(base, strings.TrimPrefix(pat, "/etc/ssh/"))
					}
					ms, _ := filepath.Glob(pat)
					sort.Strings(ms)
					for _, m := range ms {
						_ = load(m, depth+1)
						if stopped {
							return nil
						}
					}
				}
				continue
			}
			cfg.values[key] = append(cfg.values[key], strings.Join(fields[1:], " "))
		}
		return s.Err()
	}
	if err := load(path, 0); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseTimeSeconds accepts OpenSSH-style time values like "30", "30s",
// "1m", "1h", returning the value in seconds (best effort; 0 on parse fail).
func parseTimeSeconds(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	mult := 1
	switch s[len(s)-1] {
	case 's', 'S':
		s = s[:len(s)-1]
	case 'm', 'M':
		s = s[:len(s)-1]
		mult = 60
	case 'h', 'H':
		s = s[:len(s)-1]
		mult = 3600
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n * mult
}

func equalsAnyFold(s string, candidates ...string) bool {
	for _, c := range candidates {
		if strings.EqualFold(s, c) {
			return true
		}
	}
	return false
}

func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

func init() {
	register(CheckInfo{ID: "ssh:root-password-login", Rule: "ssh-config", Severity: finding.SeverityCritical,
		Description: "PermitRootLogin yes with password authentication (Critical without fail2ban/sshguard)"})
}

// bruteForceGuard names an installed SSH brute-force protector, or "".
func bruteForceGuard(facts *collector.Facts) string {
	if facts == nil {
		return ""
	}
	for _, p := range facts.Packages {
		switch p.Name {
		case "fail2ban", "fail2ban-server", "sshguard", "crowdsec", "denyhosts":
			return p.Name
		}
	}
	for _, s := range facts.Services {
		for _, n := range []string{"fail2ban", "sshguard", "crowdsec"} {
			if strings.HasPrefix(s.Name, n) {
				return s.Name
			}
		}
	}
	return ""
}
