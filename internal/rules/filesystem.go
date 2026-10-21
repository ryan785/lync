package rules

import (
	"context"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// FilesystemRule scans a small set of critical directories for
// world-writable files and unexpected setuid binaries. Bounded scope to
// keep scan time predictable — full filesystem traversal is left to a
// dedicated audit tool.
type FilesystemRule struct {
	scanRoots    []string
	suidBaseline map[string]bool
}

func NewFilesystemRule() *FilesystemRule {
	return &FilesystemRule{
		scanRoots: []string{"/etc", "/usr/local", "/opt"},
		// Common-and-expected setuid binaries. Anything outside this set in
		// /usr/bin or /usr/sbin will be flagged.
		suidBaseline: map[string]bool{
			"/usr/bin/su":                   true,
			"/usr/bin/sudo":                 true,
			"/usr/bin/passwd":               true,
			"/usr/bin/gpasswd":              true,
			"/usr/bin/chage":                true,
			"/usr/bin/chsh":                 true,
			"/usr/bin/chfn":                 true,
			"/usr/bin/newgrp":               true,
			"/usr/bin/mount":                true,
			"/usr/bin/umount":               true,
			"/usr/bin/crontab":              true,
			"/usr/bin/at":                   true,
			"/usr/bin/pkexec":               true,
			"/usr/bin/fusermount":           true,
			"/usr/bin/fusermount3":          true,
			"/usr/bin/ksu":                  true,
			"/usr/bin/staprun":              true,
			"/usr/sbin/pam_timestamp_check": true,
			"/usr/sbin/unix_chkpwd":         true,
			"/usr/libexec/dbus-1/dbus-daemon-launch-helper": true,
			"/usr/libexec/openssh/ssh-keysign":              true,
			"/usr/libexec/polkit-agent-helper-1":            true,
			"/usr/libexec/qemu-bridge-helper":               true,
			"/usr/libexec/sssd/krb5_child":                  true,
			"/usr/libexec/sssd/ldap_child":                  true,
			"/usr/libexec/sssd/selinux_child":               true,
			"/usr/libexec/sssd/proxy_child":                 true,
			"/usr/sbin/grub2-set-bootflag":                  true,
			"/usr/sbin/mount.nfs":                           true,
			"/usr/sbin/userhelper":                          true,
			"/usr/sbin/usernetctl":                          true,
		},
	}
}

func (r *FilesystemRule) Name() string { return "filesystem" }

func (r *FilesystemRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	var out []finding.Finding
	now := time.Now()

	for _, root := range r.scanRoots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if path == "/etc/lync" || path == "/etc/letsencrypt/archive" {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			mode := info.Mode()
			// World-writable file (other-write bit set, not a symlink, not socket)
			if mode&0o002 != 0 && mode&fs.ModeSymlink == 0 && mode.IsRegular() {
				out = append(out, finding.Finding{
					ID:          "fs:world-writable:" + path,
					Category:    finding.CategoryFilesystem,
					Severity:    finding.SeverityHigh,
					Title:       "World-writable file under " + root + ": " + path,
					Evidence:    "mode " + mode.String(),
					Remediation: "chmod o-w " + path,
					DetectedAt:  now,
					Source:      "lync-rules",
				})
			}
			return nil
		})
	}

	// Setuid scan limited to /usr/bin, /usr/sbin, /usr/libexec — where
	// setuids should live. Anything outside the baseline is flagged.
	for _, root := range []string{"/usr/bin", "/usr/sbin", "/usr/libexec"} {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			mode := info.Mode()
			if mode&fs.ModeSetuid == 0 {
				return nil
			}
			if r.suidBaseline[path] {
				return nil
			}
			// Suppress documentation directories that aren't real binaries.
			if strings.Contains(path, "/man/") {
				return nil
			}
			out = append(out, finding.Finding{
				ID:          "fs:unexpected-setuid:" + path,
				Category:    finding.CategoryFilesystem,
				Severity:    finding.SeverityMedium,
				Title:       "Setuid binary not in baseline: " + path,
				Evidence:    "mode " + mode.String() + " (owner: setuid)",
				Remediation: "Verify the binary is intentional. If unneeded, chmod u-s " + path,
				DetectedAt:  now,
				Source:      "lync-rules",
			})
			return nil
		})
	}

	log.Debug("filesystem rule scanned", "findings", len(out))
	return out
}
