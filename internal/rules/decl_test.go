package rules

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// testSecret is the value vectors use for secrets; it must never reach a
// finding.
const testSecret = "lync-test-secret"

var osLike = map[string][]string{
	"rocky": {"rhel", "centos", "fedora"}, "almalinux": {"rhel", "centos", "fedora"}, "rhel": {"fedora"},
	"centos": {"rhel", "fedora"}, "ol": {"fedora"}, "ubuntu": {"debian"}, "linuxmint": {"ubuntu", "debian"},
	"opensuse-leap": {"suse", "opensuse"}, "sles": {"suse"},
}

func parseVectorOS(s string) collector.OSInfo {
	id, ver, _ := strings.Cut(s, ":")
	return collector.OSInfo{ID: id, VersionID: ver, IDLike: osLike[id]}
}

func parseMeta(s string) (FileMeta, error) {
	f := strings.Fields(s)
	if len(f) != 3 {
		return FileMeta{}, fmt.Errorf("meta %q: want \"[dls]MODE UID GID\"", s)
	}
	var typ fs.FileMode
	m := f[0]
	switch m[0] {
	case 'd':
		typ, m = fs.ModeDir, m[1:]
	case 'l':
		typ, m = fs.ModeSymlink, m[1:]
	case 's':
		typ, m = fs.ModeSocket, m[1:]
	}
	n, err := strconv.ParseUint(m, 8, 32)
	if err != nil {
		return FileMeta{}, fmt.Errorf("meta %q: %v", s, err)
	}
	mode := typ | fs.FileMode(n&0o777)
	if n&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}
	if n&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}
	if n&0o1000 != 0 {
		mode |= fs.ModeSticky
	}
	uid, err1 := strconv.Atoi(f[1])
	gid, err2 := strconv.Atoi(f[2])
	if err1 != nil || err2 != nil {
		return FileMeta{}, fmt.Errorf("meta %q: bad uid/gid", s)
	}
	return FileMeta{Mode: mode, UID: uid, GID: gid, HasOwner: true}, nil
}

func mergeMap(base, over map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if v == "!absent" {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

// vectorHost builds a fixture host + facts from a pack's test_base and a vector.
func vectorHost(t *testing.T, base, v *Vector) (*Host, *collector.Facts) {
	t.Helper()
	if base == nil {
		base = &Vector{}
	}
	files := mergeMap(base.Files, v.Files)
	metas := mergeMap(base.Meta, v.Meta)
	links := mergeMap(base.Links, v.Links)
	cmds := mergeMap(base.Cmds, v.Cmds)
	pkgs := mergeMap(base.Packages, v.Packages)
	osStr := v.OS
	if osStr == "" {
		osStr = base.OS
	}
	h := &Host{Root: t.TempDir(), Meta: map[string]FileMeta{}, Links: map[string]string{}, Now: func() time.Time { return fixedNow }}
	write := func(p, body string) {
		local := h.P(p)
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(local, 0o755); err != nil {
				t.Fatal(err)
			}
			return
		}
		if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(local, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for p, body := range files {
		write(p, body)
	}
	for p, target := range links {
		if _, ok := files[p]; !ok {
			write(p, "")
		}
		h.Links[p] = target
		if _, ok := metas[p]; !ok {
			metas[p] = "l0777 0 0"
		}
	}
	for p, m := range metas {
		fm, err := parseMeta(m)
		if err != nil {
			t.Fatal(err)
		}
		if fm.Mode.IsDir() {
			if err := os.MkdirAll(h.P(p), 0o755); err != nil {
				t.Fatal(err)
			}
		} else if _, ok := files[p]; !ok {
			if _, err := os.Stat(h.P(p)); err != nil {
				write(p, "")
			}
		}
		h.Meta[p] = fm
	}
	h.Exec = func(ctx context.Context, name string, args ...string) (string, error) {
		key := strings.TrimSpace(name + " " + strings.Join(args, " "))
		out, ok := cmds[key]
		if !ok || out == "!fail" {
			return "", errors.New("exec: " + name + ": not found (fixture)")
		}
		return out, nil
	}
	facts := &collector.Facts{OS: parseVectorOS(osStr)}
	for _, n := range sortedKeys(pkgs) {
		ver := pkgs[n]
		p := collector.Package{Name: n, Manager: "rpm"}
		if e, rest, ok := strings.Cut(ver, ":"); ok {
			p.Epoch, _ = strconv.Atoi(e)
			ver = rest
		}
		if i := strings.LastIndexByte(ver, '-'); i > 0 {
			p.Version, p.Release = ver[:i], ver[i+1:]
		} else {
			p.Version = ver
		}
		facts.Packages = append(facts.Packages, p)
	}
	return h, facts
}

func runVector(t *testing.T, c *Check, v *Vector) checkResult {
	h, facts := vectorHost(t, c.pack.TestBase, v)
	env := newEvalEnv(h, facts, Options{Level: LevelStrict, Host: h})
	return env.evalCheck(context.Background(), c)
}

func TestPackLoadErrors(t *testing.T) {
	for _, err := range PackErrors() {
		t.Error(err)
	}
	if len(Packs()) == 0 {
		t.Fatal("no packs loaded")
	}
}

// TestPackVectors runs every check against its embedded vectors.
func TestPackVectors(t *testing.T) {
	for _, p := range Packs() {
		for _, c := range p.Checks {
			c := c
			t.Run(c.ID, func(t *testing.T) {
				kinds := []struct {
					name string
					vs   vectorList
				}{{"pass", c.Tests.Pass}, {"fail", c.Tests.Fail}, {"na", c.Tests.NA}, {"skip", c.Tests.Skip}}
				for _, k := range kinds {
					for i, v := range k.vs {
						res := runVector(t, c, v)
						label := fmt.Sprintf("%s vector #%d %s", k.name, i+1, v.Name)
						if res.status != k.name {
							t.Errorf("%s: got %s (%s) %v", label, res.status, res.reason, findingSummaries(res.findings))
							continue
						}
						if k.name != "fail" {
							continue
						}
						if v.Findings > 0 && len(res.findings) != v.Findings {
							t.Errorf("%s: %d findings, want %d: %v", label, len(res.findings), v.Findings, findingSummaries(res.findings))
						}
						want := c.sev
						if v.Severity != "" {
							want, _ = parseSeverity(v.Severity)
						}
						for _, f := range res.findings {
							if f.Severity != want {
								t.Errorf("%s: %s severity %s, want %s", label, f.ID, f.Severity, want)
							}
							if f.ID != c.ID && !strings.HasPrefix(f.ID, c.ID+":") {
								t.Errorf("%s: finding id %s outside check id", label, f.ID)
							}
							if f.Title == "" || f.Evidence == "" || f.Remediation == "" || f.Check != c.ID || f.Pack != p.Name || f.DetectedAt.IsZero() {
								t.Errorf("%s: incomplete finding %+v", label, f)
							}
							for _, s := range []string{f.Title, f.Evidence, f.Remediation} {
								if strings.Contains(s, testSecret) {
									t.Errorf("%s: finding leaks a secret value: %q", label, s)
								}
							}
						}
					}
				}
			})
		}
	}
}

func findingSummaries(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID+" ["+string(f.Severity)+"] "+f.Evidence)
	}
	return out
}

// baselinePacks apply to every Linux host, so they need no applies_if.
var baselinePacks = map[string]bool{
	"hardening": true, "kernel": true, "accounts": true, "filesystem": true, "boot": true, "logging": true,
	"sudo": true, "cron": true, "secrets": true, "login-defs": true, "mount": true, "pam": true, "network": true,
	"modules": true, "firewall": true, "mac": true, "services-legacy": true, "updates": true, "time": true,
	"tls": true, "audit": true, "eol": true,
}

// TestPackLint enforces the authoring rules for every check.
func TestPackLint(t *testing.T) {
	ids := map[string]bool{}
	total := 0
	for _, p := range Packs() {
		if p.AppliesIf == nil && !baselinePacks[p.Name] {
			for _, c := range p.Checks {
				if c.AppliesIf == nil {
					t.Errorf("%s: service pack %s has no applies_if (pack or check level)", c.ID, p.Name)
				}
			}
		}
		for _, c := range p.Checks {
			total++
			if ids[c.ID] {
				t.Errorf("duplicate id %s", c.ID)
			}
			ids[c.ID] = true
			if len(c.Tests.Pass) == 0 || len(c.Tests.Fail) == 0 {
				t.Errorf("%s: needs at least one pass and one fail vector", c.ID)
			}
			if len(c.References)+len(p.References) == 0 {
				t.Errorf("%s: no references", c.ID)
			}
			if len(c.Title) > 120 {
				t.Errorf("%s: title too long", c.ID)
			}
			if c.Description == "" {
				t.Errorf("%s: missing description", c.ID)
			}
			if c.sev == finding.SeverityCritical && c.level == LevelStrict {
				t.Errorf("%s: a Critical check should not be strict-only", c.ID)
			}
		}
	}
	t.Logf("%d declarative checks in %d packs", total, len(Packs()))
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"requirepass " + testSecret:                          "requirepass <redacted>",
		"DB_PASSWORD=" + testSecret:                          "DB_PASSWORD=<redacted>",
		"PasswordAuthentication yes":                         "PasswordAuthentication yes",
		"url=https://user:" + testSecret + "@example.org/x":  "url=https://user:<redacted>@example.org/x",
		"token ghp_" + strings.Repeat("a1", 15):              "token <redacted token>",
		"ssl_certificate_key /etc/ssl/private/site.key":      "ssl_certificate_key /etc/ssl/private/site.key",
		"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE": "<redacted private key>",
	}
	for in, want := range cases {
		if got := redact(in); got != want {
			t.Errorf("redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCondParse(t *testing.T) {
	good := []string{"value eq 2", "mode perm_max 0640", "value in no, prohibit-password", "x regex ^a|b$", "v empty", "v version_lt 1.2.3", "a eq 1 || b eq 2"}
	for _, s := range good {
		if _, err := parseCondGroup(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"value", "value foo 1", "v lt abc", "v perm_max 9", "v empty x"} {
		if _, err := parseCondGroup(s); err == nil {
			t.Errorf("%q: want error", s)
		}
	}
	o := obs{"mode": "0644", "v": "Prohibit-Password", "n": "abc"}
	g, _ := parseCondGroup("mode perm_max 0640")
	if ok, known := g.eval(o); ok || !known {
		t.Error("0644 is not within 0640")
	}
	g, _ = parseCondGroup("v in no,prohibit-password")
	if ok, _ := g.eval(o); !ok {
		t.Error("in should be case-insensitive")
	}
	g, _ = parseCondGroup("n gt 3")
	if _, known := g.eval(o); known {
		t.Error("non-numeric must be unknown")
	}
	g, _ = parseCondGroup("missing eq x")
	if _, known := g.eval(o); known {
		t.Error("missing field must be unknown")
	}
}

func TestCommandAllowlist(t *testing.T) {
	for _, ok := range [][]string{{"sshd", "-T"}, {"systemctl", "show", "nginx.service"}, {"docker", "inspect", "abc"}} {
		if !cmdAllowed(ok) {
			t.Errorf("%v should be allowed", ok)
		}
	}
	for _, bad := range [][]string{{"rm", "-rf", "/"}, {"postconf", "-e", "x=y"}, {"sshd", "-T", "-f", "/tmp/x"}, {"wg", "show", "all", "private-key"}, {"sh", "-c", "id"}} {
		if cmdAllowed(bad) {
			t.Errorf("%v must not be allowed", bad)
		}
	}
	if _, err := parsePack("x.yaml", []byte("pack: x\ntitle: X\nchecks:\n- id: x:y\n  title: t\n  description: d\n  severity: low\n  remediation: r\n  probe: {type: command, cmd: [sh, -c, id]}\n  expect: [output empty]\n")); err == nil {
		t.Error("pack with a non-allowlisted command must be rejected")
	}
}
