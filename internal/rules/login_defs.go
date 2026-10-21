package rules

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// LoginDefsRule audits /etc/login.defs password-aging and /etc/security/
// pwquality.conf strength settings. Both files are RHEL/Debian/SUSE
// portable so this rule applies broadly.
type LoginDefsRule struct {
	loginDefsPath string
	pwQualityPath string
}

func NewLoginDefsRule() *LoginDefsRule {
	return &LoginDefsRule{
		loginDefsPath: "/etc/login.defs",
		pwQualityPath: "/etc/security/pwquality.conf",
	}
}

func (r *LoginDefsRule) Name() string { return "login-defs" }

func (r *LoginDefsRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	var out []finding.Finding
	now := time.Now()
	mk := func(minLevel Level, id, title, evidence string, sev finding.Severity, fix string) {
		if minLevel > opts.Level {
			return
		}
		out = append(out, finding.Finding{
			ID:          "login-defs:" + id,
			Category:    finding.CategoryConfig,
			Severity:    sev,
			Title:       title,
			Evidence:    evidence,
			Remediation: fix,
			DetectedAt:  now,
			Source:      "lync-rules",
		})
	}

	if defs, err := readKVConfig(r.loginDefsPath); err == nil {
		if n, ok := intVal(defs["PASS_MAX_DAYS"]); ok && (n <= 0 || n > 365) {
			mk(LevelMedium, "pass-max-days",
				fmt.Sprintf("Password maximum age is %d (>365 or unlimited)", n),
				"PASS_MAX_DAYS "+defs["PASS_MAX_DAYS"],
				finding.SeverityMedium,
				"set PASS_MAX_DAYS to 90 (or whatever your policy allows) in /etc/login.defs")
		}
		if n, ok := intVal(defs["PASS_MIN_DAYS"]); ok && n < 1 {
			mk(LevelMedium, "pass-min-days",
				"Password minimum age is 0 (users can rotate passwords instantly to defeat reuse policy)",
				"PASS_MIN_DAYS "+defs["PASS_MIN_DAYS"],
				finding.SeverityLow,
				"set PASS_MIN_DAYS 1 in /etc/login.defs")
		}
		if n, ok := intVal(defs["PASS_WARN_AGE"]); ok && n < 7 {
			mk(LevelStrict, "pass-warn-age",
				fmt.Sprintf("Password expiry warning is only %d days (recommended >= 7)", n),
				"PASS_WARN_AGE "+defs["PASS_WARN_AGE"],
				finding.SeverityLow,
				"set PASS_WARN_AGE 7 in /etc/login.defs")
		}
		if n, ok := intVal(defs["UMASK"]); ok && n < 0o27 {
			mk(LevelStrict, "umask",
				fmt.Sprintf("Default UMASK is %o (recommended 027 or stricter)", n),
				"UMASK "+defs["UMASK"],
				finding.SeverityLow,
				"set UMASK 027 in /etc/login.defs to make new files non-world-readable by default")
		}
		if v := strings.ToUpper(defs["ENCRYPT_METHOD"]); v != "" && v != "SHA512" && v != "YESCRYPT" {
			mk(LevelMedium, "encrypt-method",
				"Weak password hashing algorithm: "+v,
				"ENCRYPT_METHOD "+v,
				finding.SeverityHigh,
				"set ENCRYPT_METHOD SHA512 (or YESCRYPT on newer systems) in /etc/login.defs")
		}
	}

	if pw, err := readKVConfig(r.pwQualityPath); err == nil {
		if n, ok := intVal(pw["minlen"]); ok && n < 12 {
			mk(LevelMedium, "pw-minlen",
				fmt.Sprintf("Password minimum length is %d (recommended >= 12)", n),
				"minlen = "+pw["minlen"],
				finding.SeverityMedium,
				"set minlen = 12 (or stricter) in /etc/security/pwquality.conf")
		}
		if n, ok := intVal(pw["dcredit"]); ok && n >= 0 {
			mk(LevelStrict, "pw-dcredit",
				"Password policy doesn't require a digit",
				"dcredit = "+pw["dcredit"],
				finding.SeverityLow,
				"set dcredit = -1 (require at least one digit)")
		}
		if n, ok := intVal(pw["ucredit"]); ok && n >= 0 {
			mk(LevelStrict, "pw-ucredit",
				"Password policy doesn't require an uppercase letter",
				"ucredit = "+pw["ucredit"],
				finding.SeverityLow,
				"set ucredit = -1")
		}
		if n, ok := intVal(pw["lcredit"]); ok && n >= 0 {
			mk(LevelStrict, "pw-lcredit",
				"Password policy doesn't require a lowercase letter",
				"lcredit = "+pw["lcredit"],
				finding.SeverityLow,
				"set lcredit = -1")
		}
		if n, ok := intVal(pw["ocredit"]); ok && n >= 0 {
			mk(LevelStrict, "pw-ocredit",
				"Password policy doesn't require a special character",
				"ocredit = "+pw["ocredit"],
				finding.SeverityLow,
				"set ocredit = -1")
		}
	}

	log.Debug("login-defs rule scanned", "level", opts.Level.String(), "findings", len(out))
	return out
}

// readKVConfig parses simple "KEY value" or "KEY = value" lines from
// /etc/login.defs and pwquality.conf, returning a map keyed by the
// canonical key (case preserved for login.defs, lowercased for pwquality).
// Both formats are tolerated by treating "=" and whitespace as separators.
func readKVConfig(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// strip trailing "# comment"
		if i := strings.Index(line, "#"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		// "KEY = value" -> two parts; "KEY  value" -> Fields
		var key, val string
		if eq := strings.Index(line, "="); eq > 0 {
			key = strings.TrimSpace(line[:eq])
			val = strings.TrimSpace(line[eq+1:])
		} else {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			key = f[0]
			val = strings.Join(f[1:], " ")
		}
		out[key] = val
	}
	return out, s.Err()
}

// intVal parses a string as int. Handles octal ("027") and decimal.
// Returns (0, false) on failure.
func intVal(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if strings.HasPrefix(s, "0") && len(s) > 1 {
		if n, err := strconv.ParseInt(s, 8, 32); err == nil {
			return int(n), true
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}
