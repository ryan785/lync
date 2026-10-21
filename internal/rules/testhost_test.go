package rules

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// fixtureHost is a Host rooted at a temp dir with faked commands and POSIX
// metadata, so every check runs identically on Windows and Linux.
type fixtureHost struct {
	t    *testing.T
	h    *Host
	cmds map[string]string // "name arg1 arg2" -> stdout; missing = tool error
}

var fixedNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func newFixture(t *testing.T) *fixtureHost {
	t.Helper()
	fx := &fixtureHost{t: t, cmds: map[string]string{}}
	fx.h = &Host{
		Root: t.TempDir(),
		Meta: map[string]FileMeta{},
		Now:  func() time.Time { return fixedNow },
	}
	fx.h.Exec = func(ctx context.Context, name string, args ...string) (string, error) {
		key := strings.TrimSpace(name + " " + strings.Join(args, " "))
		if out, ok := fx.cmds[key]; ok {
			return out, nil
		}
		return "", errors.New("exec: " + name + ": not found (fixture)")
	}
	return fx
}

// file writes content at a host path.
func (fx *fixtureHost) file(p, content string) *fixtureHost {
	fx.t.Helper()
	local := fx.h.P(p)
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		fx.t.Fatal(err)
	}
	if err := os.WriteFile(local, []byte(content), 0o644); err != nil {
		fx.t.Fatal(err)
	}
	return fx
}

func (fx *fixtureHost) dir(p string) *fixtureHost {
	fx.t.Helper()
	if err := os.MkdirAll(fx.h.P(p), 0o755); err != nil {
		fx.t.Fatal(err)
	}
	return fx
}

// meta sets POSIX mode/owner for a host path (dirs: include fs.ModeDir).
func (fx *fixtureHost) meta(p string, mode fs.FileMode, uid, gid int) *fixtureHost {
	fx.h.Meta[p] = FileMeta{Mode: mode, UID: uid, GID: gid, HasOwner: true}
	return fx
}

func (fx *fixtureHost) cmd(line, out string) *fixtureHost {
	fx.cmds[line] = out
	return fx
}

func (fx *fixtureHost) opts() Options {
	return Options{Level: LevelMedium, Host: fx.h}
}

func runRule(r Rule, facts *collector.Facts, o Options) []finding.Finding {
	if facts == nil {
		facts = &collector.Facts{}
	}
	return r.Run(context.Background(), facts, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), o)
}

// ids returns finding IDs for compact assertions.
func ids(fs []finding.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.ID
	}
	return out
}

func hasID(fs []finding.Finding, id string) *finding.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func hasPrefix(fs []finding.Finding, prefix string) int {
	n := 0
	for _, f := range fs {
		if strings.HasPrefix(f.ID, prefix) {
			n++
		}
	}
	return n
}

// requireShape asserts every finding has the shared-shape essentials.
func requireShape(t *testing.T, fs []finding.Finding) {
	t.Helper()
	for _, f := range fs {
		if f.ID == "" || f.Severity == "" || f.Title == "" || f.Evidence == "" || f.Remediation == "" || f.Source != "lync-rules" || f.DetectedAt.IsZero() {
			t.Errorf("finding missing shared-shape fields: %+v", f)
		}
		if _, ok := catalog[checkIDOf(f.ID)]; !ok {
			t.Errorf("finding %s has no catalog entry", f.ID)
		}
	}
}

const passwdFixture = `root:x:0:0:root:/root:/bin/bash
nginx:x:991:991:Nginx:/var/lib/nginx:/sbin/nologin
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
deploy:x:1001:1001::/home/deploy:/bin/bash
`

const groupFixture = `root:x:0:
nginx:x:991:
apache:x:48:nginx
docker:x:992:alice,deploy
wheel:x:10:alice
`
