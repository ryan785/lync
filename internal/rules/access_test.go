package rules

import (
	"io/fs"
	"reflect"
	"testing"

	"github.com/ryan785/lync/internal/finding"
)

func accessFixture(t *testing.T) *fixtureHost {
	fx := newFixture(t)
	fx.file("/etc/passwd", passwdFixture).file("/etc/group", groupFixture).
		file("/etc/sudoers", "root ALL=(ALL) ALL\n# deploy ALL=(ALL) NOPASSWD: ALL\n%wheel ALL=(ALL) ALL\n").
		file("/etc/sudoers.d/90-cloud", "alice ALL=(ALL) NOPASSWD:ALL\n").
		file("/etc/sudoers.d/backup", "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart app\n").
		file("/home/alice/.ssh/authorized_keys", "ssh-ed25519 AAA alice").
		meta("/home/alice/.ssh", fs.ModeDir|0o775, 1000, 1000).
		meta("/home/alice/.ssh/authorized_keys", 0o600, 1000, 1000).
		file("/home/deploy/.ssh/authorized_keys", "ssh-ed25519 AAA deploy").
		meta("/home/deploy/.ssh/authorized_keys", 0o644, 1000, 1000). // owned by alice
		file("/var/run/docker.sock", "").meta("/var/run/docker.sock", fs.ModeSocket|0o666, 0, 992).
		file("/etc/systemd/system/rustdesk-relay.service", "[Service]\nExecStart=/opt/hbbr --key=x\nEnvironment=API_TOKEN=abcd1234\nEnvironment=LOG=1\n").
		file("/etc/systemd/system/clean.service", "[Service]\nEnvironment=TOKEN_FILE=$CREDENTIALS_DIRECTORY/t\n").
		file("/opt/twenty/docker-compose.yml", "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: hunter2\n      APP_SECRET: ${APP_SECRET}\n").
		meta("/opt/twenty/docker-compose.yml", 0o644, 0, 0).
		file("/opt/twenty/.env", "APP_SECRET=zzz\n").meta("/opt/twenty/.env", 0o600, 0, 0).
		file("/root/app/.env", "DB_PASSWORD=x\n").meta("/root/app/.env", 0o644, 0, 0).meta("/root", fs.ModeDir|0o550, 0, 0).
		dir("/etc/app/drop").meta("/etc/app/drop", fs.ModeDir|0o777, 0, 0).
		dir("/etc/app/tmp").meta("/etc/app/tmp", fs.ModeDir|fs.ModeSticky|0o777, 0, 0).
		file("/etc/crontab", "SHELL=/bin/bash\n0 3 * * * root /usr/local/bin/backup.sh >/dev/null 2>&1\n*/5 * * * * alice /home/alice/x.sh\n").
		file("/usr/local/bin/backup.sh", "#!/bin/sh").meta("/usr/local/bin/backup.sh", 0o777, 0, 0).
		file("/var/spool/cron/root", "@reboot /opt/scripts/start.sh\n").
		file("/opt/scripts/start.sh", "#!/bin/sh").meta("/opt/scripts/start.sh", 0o755, 1000, 1000).
		file("/etc/cron.daily/logrotate", "#!/bin/sh").meta("/etc/cron.daily/logrotate", 0o755, 0, 0)
	return fx
}

func TestAccessRule(t *testing.T) {
	fx := accessFixture(t)
	got := runRule(NewAccessRule(), nil, fx.opts())
	requireShape(t, got)
	want := map[string]finding.Severity{
		"account:sudo-nopasswd:/etc/sudoers.d/90-cloud:1":                   finding.SeverityHigh,
		"account:sudo-nopasswd:/etc/sudoers.d/backup:1":                     finding.SeverityMedium,
		"account:ssh-perms:/home/alice/.ssh":                                finding.SeverityHigh,
		"account:ssh-perms:/home/deploy/.ssh/authorized_keys":               finding.SeverityHigh,
		"docker:group-members":                                              finding.SeverityMedium,
		"docker:socket-perms:/var/run/docker.sock":                          finding.SeverityCritical,
		"secrets:world-readable:/etc/systemd/system/rustdesk-relay.service": finding.SeverityHigh,
		"secrets:world-readable:/opt/twenty/docker-compose.yml":             finding.SeverityHigh,
		"fs:world-writable-dir:/etc/app/drop":                               finding.SeverityHigh,
		"cron:writable-script:/usr/local/bin/backup.sh":                     finding.SeverityCritical,
		"cron:writable-script:/opt/scripts/start.sh":                        finding.SeverityCritical,
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
	for _, id := range []string{
		"account:sudo-nopasswd:/etc/sudoers:2",                     // commented out
		"secrets:world-readable:/etc/systemd/system/clean.service", // variable reference only
		"secrets:world-readable:/opt/twenty/.env",                  // 0600
		"secrets:world-readable:/root/app/.env",                    // /root not traversable
		"fs:world-writable-dir:/etc/app/tmp",                       // sticky
		"cron:writable-script:/home/alice/x.sh",                    // not a root job
		"cron:writable-script:/etc/cron.daily/logrotate",
	} {
		if hasID(got, id) != nil {
			t.Errorf("unexpected %s", id)
		}
	}
	// Secret values must never appear in findings.
	for _, f := range got {
		for _, secret := range []string{"hunter2", "abcd1234"} {
			if contains(f.Evidence, secret) || contains(f.Title, secret) {
				t.Errorf("finding %s leaks a secret value", f.ID)
			}
		}
	}
	if f := hasID(got, "secrets:world-readable:/opt/twenty/docker-compose.yml"); f != nil && !contains(f.Evidence, "POSTGRES_PASSWORD") {
		t.Errorf("evidence should name the key: %q", f.Evidence)
	}
}

func TestSecretKeys(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"DB_PASSWORD=abc\nexport API_KEY='k'\n", []string{"API_KEY", "DB_PASSWORD"}},
		{"ExecStart=/usr/bin/agent --token abc123 --verbose", []string{"--token"}},
		{"PASSWORD=${PASSWORD}\n# SECRET=x\nTOKEN=\n", nil},
		{"MINIO_ROOT_PASSWORD: \"minio123\"", []string{"MINIO_ROOT_PASSWORD"}},
	}
	for _, c := range cases {
		if got := secretKeys(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("secretKeys(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAccessRuleEmptyHost(t *testing.T) {
	fx := newFixture(t)
	if got := runRule(NewAccessRule(), nil, fx.opts()); len(got) != 0 {
		t.Errorf("empty host: got %v", ids(got))
	}
}
