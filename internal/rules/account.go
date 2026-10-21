package rules

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// AccountRule parses /etc/passwd + /etc/shadow looking for:
//   - non-root UID 0 accounts
//   - empty password fields in /etc/shadow
//   - accounts with valid shells but locked passwords (less actionable;
//     left for a future iteration)
type AccountRule struct {
	passwdPath string
	shadowPath string
}

func NewAccountRule() *AccountRule {
	return &AccountRule{
		passwdPath: "/etc/passwd",
		shadowPath: "/etc/shadow",
	}
}

func (r *AccountRule) Name() string { return "accounts" }

func (r *AccountRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	var out []finding.Finding
	now := time.Now()

	if entries, err := readPasswd(r.passwdPath); err == nil {
		for _, e := range entries {
			if e.uid == 0 && e.name != "root" {
				out = append(out, finding.Finding{
					ID:          "account:uid0-" + e.name,
					Category:    finding.CategoryConfig,
					Severity:    finding.SeverityCritical,
					Title:       "Non-root account with UID 0: " + e.name,
					Evidence:    e.raw,
					Remediation: "Remove the user (userdel " + e.name + ") or change its UID. UID 0 grants full root privilege; only the root account should have it.",
					DetectedAt:  now,
					Source:      "lync-rules",
				})
			}
		}
	}

	if entries, err := readShadow(r.shadowPath); err == nil {
		for _, e := range entries {
			if e.empty {
				out = append(out, finding.Finding{
					ID:          "account:empty-pwd-" + e.name,
					Category:    finding.CategoryConfig,
					Severity:    finding.SeverityCritical,
					Title:       "Account with empty password: " + e.name,
					Evidence:    "shadow entry for " + e.name + " has no password hash",
					Remediation: "passwd -l " + e.name + " (lock) or set a strong password",
					DetectedAt:  now,
					Source:      "lync-rules",
				})
			}
		}
	} else {
		log.Debug("shadow unreadable (rule requires root)", "err", err)
	}

	log.Debug("accounts rule scanned", "findings", len(out))
	return out
}

type passwdEntry struct {
	name string
	uid  int
	raw  string
}

func readPasswd(path string) ([]passwdEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []passwdEntry
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		var uid int
		_, _ = fmtSscanf(fields[2], &uid)
		out = append(out, passwdEntry{name: fields[0], uid: uid, raw: line})
	}
	return out, s.Err()
}

type shadowEntry struct {
	name  string
	empty bool
}

func readShadow(path string) ([]shadowEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []shadowEntry
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Split(s.Text(), ":")
		if len(fields) < 2 {
			continue
		}
		out = append(out, shadowEntry{
			name:  fields[0],
			empty: fields[1] == "",
		})
	}
	return out, s.Err()
}

// fmtSscanf is a tiny strconv wrapper so we can avoid importing fmt/strconv
// in two more places.
func fmtSscanf(s string, out *int) (int, error) {
	n := 0
	read := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
		read++
	}
	*out = n
	return read, nil
}
