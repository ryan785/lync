package rules

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// writeTempConfig drops content into a tempfile and returns its path,
// auto-cleaned via t.Cleanup.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

func findByID(findings []finding.Finding, id string) *finding.Finding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}

func TestSSHConfigRule_PermitRootLoginYes(t *testing.T) {
	path := writeTempConfig(t, `
# comment
PermitRootLogin yes
PasswordAuthentication no
`)
	r := &SSHConfigRule{path: path}
	got := r.Run(context.Background(), &collector.Facts{},
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Options{Level: LevelBasic})
	if f := findByID(got, "ssh:permit-root-login"); f == nil {
		t.Errorf("expected ssh:permit-root-login finding; got %d findings", len(got))
	}
}

func TestSSHConfigRule_FirstWinsSemantics(t *testing.T) {
	// sshd_config(5): "the first obtained value will be used".
	path := writeTempConfig(t, `
PermitRootLogin no
PermitRootLogin yes
`)
	r := &SSHConfigRule{path: path}
	got := r.Run(context.Background(), &collector.Facts{},
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Options{Level: LevelBasic})
	if f := findByID(got, "ssh:permit-root-login"); f != nil {
		t.Errorf("expected no permit-root-login finding (first value is 'no'); got: %+v", *f)
	}
}

func TestSSHConfigRule_IncludeDropInWins(t *testing.T) {
	// RHEL 9 layout: Include at the top, drop-in sets PermitRootLogin yes,
	// main file says no later. The drop-in is first, so it wins.
	path := writeTempConfig(t, `Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin no
`)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshd_config.d", "01-permitrootlogin.conf"), []byte(`PermitRootLogin yes
`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &SSHConfigRule{path: path}
	got := r.Run(context.Background(), &collector.Facts{},
		slog.New(slog.NewTextHandler(os.Stderr, nil)), Options{Level: LevelBasic})
	if findByID(got, "ssh:permit-root-login") == nil {
		t.Errorf("drop-in PermitRootLogin yes (first match) should be flagged")
	}
	if f := findByID(got, "ssh:root-password-login"); f == nil || f.Severity != finding.SeverityCritical {
		t.Errorf("root+password login with no fail2ban should be Critical, got %+v", f)
	}
}

func TestSSHConfigRule_LevelFiltering(t *testing.T) {
	// Banner-missing is a Strict-only check. Should not appear at Basic or
	// Medium even if the config triggers it.
	path := writeTempConfig(t, `
PermitRootLogin no
Banner none
`)
	r := &SSHConfigRule{path: path}
	for _, level := range []Level{LevelBasic, LevelMedium} {
		got := r.Run(context.Background(), &collector.Facts{},
			slog.New(slog.NewTextHandler(os.Stderr, nil)),
			Options{Level: level})
		if f := findByID(got, "ssh:no-banner"); f != nil {
			t.Errorf("level=%s: did not expect ssh:no-banner; got: %+v", level, *f)
		}
	}
	got := r.Run(context.Background(), &collector.Facts{},
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Options{Level: LevelStrict})
	if f := findByID(got, "ssh:no-banner"); f == nil {
		t.Errorf("level=strict: expected ssh:no-banner; got %d findings", len(got))
	}
}

func TestSSHConfigRule_WeakCipher(t *testing.T) {
	path := writeTempConfig(t, `
Ciphers aes128-cbc,chacha20-poly1305@openssh.com
`)
	r := &SSHConfigRule{path: path}
	got := r.Run(context.Background(), &collector.Facts{},
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Options{Level: LevelMedium})
	if f := findByID(got, "ssh:weak-cipher-aes128-cbc"); f == nil {
		t.Errorf("expected weak-cipher finding for aes128-cbc; got %d findings", len(got))
	}
}

func TestSSHConfigRule_MatchBlockStopsParsing(t *testing.T) {
	// Directives inside Match blocks are conditional and should not be
	// applied at global scope.
	path := writeTempConfig(t, `
PermitRootLogin no
Match User backup
    PermitRootLogin yes
`)
	r := &SSHConfigRule{path: path}
	got := r.Run(context.Background(), &collector.Facts{},
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Options{Level: LevelBasic})
	if f := findByID(got, "ssh:permit-root-login"); f != nil {
		t.Errorf("Match-block PermitRootLogin yes should not be flagged at global scope; got: %+v", *f)
	}
}

func TestParseTimeSeconds(t *testing.T) {
	cases := map[string]int{
		"30":  30,
		"30s": 30,
		"1m":  60,
		"1h":  3600,
		"":    0,
		"foo": 0,
	}
	for in, want := range cases {
		if got := parseTimeSeconds(in); got != want {
			t.Errorf("parseTimeSeconds(%q) = %d, want %d", in, got, want)
		}
	}
}
