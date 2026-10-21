package rules

import (
	"testing"

	"github.com/ryan785/lync/internal/finding"
)

const inspectCmd = "docker inspect --format {{.Name}}|{{.Config.Image}}|{{.Image}}|{{.HostConfig.RestartPolicy.Name}}|{{.State.Status}}|{{.RestartCount}}|{{.State.Running}} a1 b2 c3 d4 e5"

func runtimeFixture(t *testing.T) *fixtureHost {
	fx := newFixture(t)
	fx.h.Links = map[string]string{
		"/proc/101/exe": "/root/.nvm/versions/node/v18.20.4/bin/node",
		"/proc/102/exe": "/usr/bin/node",
		"/proc/103/exe": "/opt/pyenv/versions/3.8.18/bin/python3.8",
		"/proc/104/exe": "/usr/bin/python3.9",
		"/proc/105/exe": "/root/.nvm/versions/node/v22.11.0/bin/node",
	}
	for _, pid := range []string{"101", "102", "103", "104", "105"} {
		fx.dir("/proc/" + pid)
	}
	fx.dir("/proc/self")
	fx.cmd("/usr/bin/node --version", "v20.18.1\n").
		cmd("docker ps -aq", "a1\nb2\nc3\nd4\ne5\n").
		cmd(inspectCmd, "/postgres|postgres:12-alpine|sha256:aaa|unless-stopped|running|0|true\n"+
			"/twenty|twentycrm/twenty:latest|sha256:bbb|always|running|0|true\n"+
			"/old-app|myapp:1.2|sha256:ccc|always|exited|37|false\n"+
			"/web|nginx:1.27|sha256:ddd|no|running|0|true\n"+
			"/poste|analogic/poste.io|sha256:eee|always|running|0|true\n").
		cmd("docker image inspect --format {{.Id}}|{{.Created}} sha256:aaa sha256:bbb sha256:ccc sha256:ddd sha256:eee",
			"sha256:aaa|2024-01-02T03:04:05.123456789Z\nsha256:bbb|2026-10-01T00:00:00Z\nsha256:ccc|2023-01-01T00:00:00Z\nsha256:ddd|2026-09-30T00:00:00Z\nsha256:eee|2025-06-01T00:00:00Z\n").
		cmd(`docker exec poste php -r echo PHP_VERSION, "|", var_export((bool)ini_get("session.upload_progress.enabled"), true);`, "8.1.2|true")
	return fx
}

func TestRuntimesRule(t *testing.T) {
	fx := runtimeFixture(t)
	got := runRule(NewRuntimesRule(), nil, fx.opts())
	requireShape(t, got)
	want := map[string]finding.Severity{
		"runtime:eol-node:/root/.nvm/versions/node/v18.20.4/bin/node": finding.SeverityHigh,
		"runtime:eol-node:/usr/bin/node":                              finding.SeverityMedium, // node 20 EOL 2026-04-30, distro path
		"runtime:eol-python:/opt/pyenv/versions/3.8.18/bin/python3.8": finding.SeverityMedium,
		"container:latest-tag:twenty":                                 finding.SeverityLow,
		"container:latest-tag:poste":                                  finding.SeverityLow,
		"container:image-age:postgres":                                finding.SeverityMedium,
		"container:image-age:poste":                                   finding.SeverityMedium,
		"container:restart-loop:old-app":                              finding.SeverityLow,
		"container:eol-base:postgres":                                 finding.SeverityMedium,
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
		"runtime:eol-node:/root/.nvm/versions/node/v22.11.0/bin/node",
		"runtime:eol-python:/usr/bin/python3.9", // distro python skipped
		"container:image-age:twenty",
		"container:eol-base:web",
		"container:php-upload-progress:poste", // default off
	} {
		if hasID(got, id) != nil {
			t.Errorf("unexpected %s", id)
		}
	}
}

func TestContainerPHPOptIn(t *testing.T) {
	fx := runtimeFixture(t)
	o := fx.opts()
	o.Toggles = Toggles{Enable: []string{"container:php-upload-progress"}}
	got := runRule(NewRuntimesRule(), nil, o)
	if f := hasID(got, "container:php-upload-progress:poste"); f == nil || f.Severity != finding.SeverityHigh {
		t.Errorf("opt-in container php check: got %v", ids(got))
	}
	// Containers without php (exec fails) are silently skipped.
	if hasID(got, "container:php-upload-progress:postgres") != nil {
		t.Error("postgres has no php; must be skipped")
	}
}

func TestEOLForAndImageRef(t *testing.T) {
	cases := []struct {
		rt, v string
		past  bool
	}{
		{"node", "18.20.4", true}, {"node", "22.1.0", false}, {"python", "3.9.2", true}, {"python", "3.12.1", false},
		{"postgres", "12", true}, {"postgres", "16.2", false}, {"php", "7.4", true}, {"php", "8.3", false},
	}
	for _, c := range cases {
		if _, _, past := eolFor(c.rt, c.v, fixedNow); past != c.past {
			t.Errorf("eolFor(%s, %s) = %v, want %v", c.rt, c.v, past, c.past)
		}
	}
	for ref, want := range map[string][2]string{
		"postgres:12-alpine":           {"postgres", "12-alpine"},
		"registry.local:5000/team/app": {"registry.local:5000/team/app", ""},
		"ghcr.io/x/y:1.2@sha256:abc":   {"ghcr.io/x/y", "1.2"},
	} {
		if r, tag := splitImageRef(ref); r != want[0] || tag != want[1] {
			t.Errorf("splitImageRef(%q) = %q, %q", ref, r, tag)
		}
	}
}

func TestSetRuntimeEOL(t *testing.T) {
	defer SetRuntimeEOL("node", nil)
	// Upstream schedule data wins over the built-in table; majors it
	// lacks fall back to the table; nil restores the table.
	SetRuntimeEOL("node", map[string]string{"22": "2026-01-01", "26": "2029-04-30"})
	if _, d, past := eolFor("node", "22.22.0", fixedNow); !past || d != "2026-01-01" {
		t.Errorf("override: eolFor(node 22) = %s, %v", d, past)
	}
	if _, _, past := eolFor("node", "18.20.4", fixedNow); !past {
		t.Error("fallback: node 18 should still be EOL")
	}
	if _, d, past := eolFor("node", "26.12.1", fixedNow); past || d != "2029-04-30" {
		t.Errorf("new major from schedule: %s, %v", d, past)
	}
	SetRuntimeEOL("node", nil)
	if _, d, past := eolFor("node", "22.22.0", fixedNow); past || d != "2027-04-30" {
		t.Errorf("restored: eolFor(node 22) = %s, %v", d, past)
	}
}

func TestRuntimesNoDocker(t *testing.T) {
	fx := newFixture(t)
	if got := runRule(NewRuntimesRule(), nil, fx.opts()); len(got) != 0 {
		t.Errorf("no docker/proc: got %v", ids(got))
	}
}
