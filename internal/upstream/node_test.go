package upstream

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/inventory"
	"github.com/ryan785/lync/internal/rules"
)

var fixedNow = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

// fixture is a rules.Host rooted at a temp dir with faked commands.
type fixture struct {
	t    *testing.T
	h    *rules.Host
	cmds map[string]string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	fx := &fixture{t: t, cmds: map[string]string{}}
	fx.h = &rules.Host{Root: t.TempDir(), Links: map[string]string{}, Now: func() time.Time { return fixedNow }}
	fx.h.Exec = func(_ context.Context, name string, args ...string) (string, error) {
		if out, ok := fx.cmds[strings.TrimSpace(name+" "+strings.Join(args, " "))]; ok {
			return out, nil
		}
		return "", errors.New("exec: " + name + ": not found (fixture)")
	}
	return fx
}

func (fx *fixture) file(p string) *fixture {
	fx.t.Helper()
	local := fx.h.P(p)
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		fx.t.Fatal(err)
	}
	if err := os.WriteFile(local, []byte("fixture binary placeholder\n"), 0o644); err != nil {
		fx.t.Fatal(err)
	}
	return fx
}

// proc registers a running process whose /proc/<pid>/exe points at exe.
func (fx *fixture) proc(pid, exe string) *fixture {
	fx.t.Helper()
	if err := os.MkdirAll(fx.h.P("/proc/"+pid), 0o755); err != nil {
		fx.t.Fatal(err)
	}
	fx.h.Links["/proc/"+pid+"/exe"] = exe
	return fx
}

// nodeServer serves the fixture data files; wg selects the security-wg
// file. It honours If-None-Match like the real endpoints.
type nodeServer struct {
	*httptest.Server
	hits atomic.Int64
	down atomic.Bool
}

func newNodeServer(t *testing.T, wg string) *nodeServer {
	t.Helper()
	files := map[string]string{
		"/dist/index.json":    "node-index.json",
		"/wg/index.json":      wg,
		"/rel/schedule.json":  "node-schedule.json",
		"/missing/index.json": "",
	}
	s := &nodeServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if s.down.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		name, ok := files[r.URL.Path]
		if !ok || name == "" {
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Error(err)
			return
		}
		etag := `"` + name + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write(data)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *nodeServer) provider(t *testing.T) *Node {
	n := NewNode(t.TempDir())
	n.IndexURL = s.URL + "/dist/index.json"
	n.VulnURL = s.URL + "/wg/index.json"
	n.ScheduleURL = s.URL + "/rel/schedule.json"
	return n
}

func env(fx *fixture, facts *collector.Facts, t rules.Toggles) Env {
	return Env{Host: fx.h, Facts: facts, Toggles: t, Now: fixedNow}
}

func TestNodeDetect(t *testing.T) {
	fx := newFixture(t)
	fx.file("/root/.nvm/versions/node/v22.22.0/bin/node").proc("101", "/root/.nvm/versions/node/v22.22.0/bin/node")
	fx.file("/home/alice/.nvm/versions/node/v22.23.4/bin/node")
	fx.file("/home/bob/.volta/tools/image/node/24.22.1/bin/node")
	fx.file("/home/bob/.local/share/fnm/node-versions/v26.12.0/installation/bin/node")
	fx.file("/home/carol/.asdf/installs/nodejs/24.18.1/bin/node")
	// /usr/local/bin/node -> tarball under /opt (one install, not two).
	fx.file("/usr/local/bin/node").file("/opt/node-v24.21.0-linux-x64/bin/node")
	fx.h.Links["/usr/local/bin/node"] = "../../../opt/node-v24.21.0-linux-x64/bin/node"
	// A tarball without the version in its path: `node --version`.
	fx.file("/opt/app/bin/node")
	fx.cmds["/opt/app/bin/node --version"] = "v26.12.0\n"
	// Unreadable version: skipped.
	fx.file("/opt/broken/bin/node")
	// Distro node (Debian nodejs package), running: not upstream.
	fx.file("/usr/bin/node").proc("102", "/usr/bin/node")
	fx.cmds["/usr/bin/node --version"] = "v18.19.0\n"
	// A process of something else.
	fx.proc("103", "/usr/sbin/nginx")
	facts := &collector.Facts{Packages: []collector.Package{{Name: "nodejs", Version: "18.19.0+dfsg-6~deb12u2", Manager: "dpkg"}}}

	got := NewNode(t.TempDir()).Detect(context.Background(), env(fx, facts, rules.Toggles{}))
	var lines []string
	for _, in := range got {
		lines = append(lines, in.Path+" "+in.Version+" "+in.Via+" pid="+in.PID)
	}
	want := []string{
		"/home/alice/.nvm/versions/node/v22.23.4/bin/node 22.23.4 nvm pid=",
		"/home/bob/.local/share/fnm/node-versions/v26.12.0/installation/bin/node 26.12.0 fnm pid=",
		"/home/bob/.volta/tools/image/node/24.22.1/bin/node 24.22.1 volta pid=",
		"/home/carol/.asdf/installs/nodejs/24.18.1/bin/node 24.18.1 asdf pid=",
		"/opt/app/bin/node 26.12.0 tarball pid=",
		"/opt/node-v24.21.0-linux-x64/bin/node 24.21.0 tarball pid=",
		"/root/.nvm/versions/node/v22.22.0/bin/node 22.22.0 nvm pid=101",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("Detect:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

func TestNodeSourcePackage(t *testing.T) {
	for _, pkg := range []collector.Package{
		{Name: "nodejs", Version: "22.22.0-1nodesource1", Arch: "amd64", Manager: "dpkg"},
		{Name: "nodejs", Version: "22.22.0", Release: "1nodesource", Epoch: 2, Arch: "x86_64", Manager: "rpm"},
	} {
		t.Run(pkg.Manager, func(t *testing.T) {
			fx := newFixture(t)
			fx.file("/usr/bin/node").proc("200", "/usr/bin/node")
			facts := &collector.Facts{Packages: []collector.Package{pkg, {Name: "openssl", Version: "3.0.15", Manager: pkg.Manager}}}
			got := NewNode(t.TempDir()).Detect(context.Background(), env(fx, facts, rules.Toggles{}))
			if len(got) != 1 || got[0].Path != "/usr/bin/node" || got[0].Version != "22.22.0" ||
				got[0].Via != "nodesource" || got[0].Package != "nodejs" || got[0].PID != "200" {
				t.Fatalf("Detect = %+v", got)
			}
			// Excluded from the distro lookup, everything else kept.
			distro := WithoutNodeSource(facts)
			if len(distro.Packages) != 1 || distro.Packages[0].Name != "openssl" {
				t.Errorf("WithoutNodeSource kept %+v", distro.Packages)
			}
			if len(facts.Packages) != 2 {
				t.Error("WithoutNodeSource modified its input")
			}

			// Matched as upstream Node 22.22.0, with the package named.
			srv := newNodeServer(t, "node-security-wg.json")
			n := srv.provider(t)
			if st := n.Fetch(context.Background()); st.Status != feed.StatusOK {
				t.Fatalf("fetch: %+v", st)
			}
			fs := n.Match(context.Background(), env(fx, facts, rules.Toggles{}), got, nil)
			f := byID(fs)["upstream:node-cve:CVE-2026-111497:/usr/bin/node"]
			if f.Package != "nodejs" || f.FixedIn != "22.23.4" || !strings.Contains(f.Remediation, "NodeSource") {
				t.Errorf("nodesource finding = %+v", f)
			}
		})
	}
}

func TestDistroNodeNotUpstream(t *testing.T) {
	fx := newFixture(t)
	fx.file("/usr/bin/node").proc("300", "/usr/bin/node")
	fx.file("/usr/bin/nodejs")
	fx.h.Links["/usr/bin/node"] = "nodejs"
	facts := &collector.Facts{Packages: []collector.Package{{Name: "nodejs", Version: "22.22.0", Release: "1.module+el9.6.0+2", Manager: "rpm"}}}
	if got := NewNode(t.TempDir()).Detect(context.Background(), env(fx, facts, rules.Toggles{})); len(got) != 0 {
		t.Errorf("distro node detected as upstream: %+v", got)
	}
	if WithoutNodeSource(facts) != facts {
		t.Error("distro nodejs package must stay in the distro lookup")
	}
}

func byID(fs []finding.Finding) map[string]finding.Finding {
	m := map[string]finding.Finding{}
	for _, f := range fs {
		m[f.ID] = f
	}
	return m
}

func ids(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	sort.Strings(out)
	return out
}

func TestNodeMatch(t *testing.T) {
	srv := newNodeServer(t, "node-security-wg.json")
	n := srv.provider(t)
	st := n.Fetch(context.Background())
	if st.Status != feed.StatusOK || st.Requests != 3 || st.Records == 0 {
		t.Fatalf("fetch stat = %+v", st)
	}
	if eol := n.EOL(); eol["22"] != "2027-04-30" || eol["20"] != "2026-04-30" || eol["26"] != "2029-04-30" {
		t.Errorf("EOL = %v", eol)
	}
	fx := newFixture(t)
	installs := []Install{
		{Runtime: "node", Path: "/root/.nvm/versions/node/v22.22.0/bin/node", Version: "22.22.0", Via: "nvm", PID: "101"},
		{Runtime: "node", Path: "/home/alice/.nvm/versions/node/v22.23.4/bin/node", Version: "22.23.4", Via: "nvm"},
		{Runtime: "node", Path: "/opt/node-v24.21.0-linux-x64/bin/node", Version: "24.21.0", Via: "tarball"},
		{Runtime: "node", Path: "/opt/app/bin/node", Version: "26.12.0", Via: "tarball"},
		{Runtime: "node", Path: "/opt/new/bin/node", Version: "26.12.1", Via: "tarball"},
		{Runtime: "node", Path: "/opt/old/bin/node", Version: "20.19.6", Via: "tarball"},
	}
	var asked []string
	enrich := func(_ context.Context, cves []string) map[string]feed.Vulnerability {
		asked = cves
		return map[string]feed.Vulnerability{"CVE-2026-111497": {ID: "CVE-2026-111497", Source: "nvd", CVSS: 9.8, Severity: "CRITICAL"}}
	}
	fs := n.Match(context.Background(), env(fx, nil, rules.Toggles{}), installs, enrich)
	m := byID(fs)

	nvm := "/root/.nvm/versions/node/v22.22.0/bin/node"
	oct22 := []string{"CVE-2026-105482", "CVE-2026-106069", "CVE-2026-111497", "CVE-2026-105481", "CVE-2026-106072", "CVE-2026-106074", "CVE-2026-106073"}
	for _, cve := range oct22 {
		f, ok := m["upstream:node-cve:"+cve+":"+nvm]
		if !ok {
			t.Errorf("22.22.0: missing %s", cve)
			continue
		}
		if f.FixedIn != "22.23.4" || f.Installed != "22.22.0" || f.Package != "node" || f.CVE != cve ||
			f.Category != finding.CategoryCVE || f.Check != CheckNodeCVE || !strings.HasPrefix(f.Source, "nodejs-security-wg") {
			t.Errorf("22.22.0 %s = %+v", cve, f)
		}
		if !strings.Contains(f.Remediation, "nvm install 22.23.4") || !strings.Contains(f.Evidence, "pid 101") {
			t.Errorf("22.22.0 %s remediation/evidence: %q / %q", cve, f.Remediation, f.Evidence)
		}
	}
	for _, cve := range []string{"CVE-2026-105483", "CVE-2026-106070", "CVE-2026-106071"} {
		if _, ok := m["upstream:node-cve:"+cve+":"+nvm]; ok {
			t.Errorf("22.22.0 flagged for %s (not on the 22 line)", cve)
		}
	}
	// The July CVEs are fixed in the July release on the 22 line.
	if f := m["upstream:node-cve:CVE-2026-58043:"+nvm]; f.FixedIn != "22.23.2" {
		t.Errorf("CVE-2026-58043 fixed_in = %q, want 22.23.2", f.FixedIn)
	}
	// Severity: security-wg, upgraded by the NVD score where there is one.
	if f := m["upstream:node-cve:CVE-2026-111497:"+nvm]; f.Severity != finding.SeverityCritical || f.CVSS != 9.8 || f.Source != "nodejs-security-wg+nvd" {
		t.Errorf("enriched finding = %+v", f)
	}
	if f := m["upstream:node-cve:CVE-2026-105482:"+nvm]; f.Severity != finding.SeverityHigh || f.CVSS != 0 {
		t.Errorf("wg severity = %s %v", f.Severity, f.CVSS)
	}
	if f := m["upstream:node-cve:CVE-2026-106073:"+nvm]; f.Severity != finding.SeverityLow {
		t.Errorf("low CVE severity = %s", f.Severity)
	}
	// CVE findings cover every missed security release: no release finding.
	if _, ok := m[CheckNodeRelease+":"+nvm]; ok {
		t.Error("22.22.0: security-release finding not collapsed into the CVE findings")
	}
	// Patched installs and EOL lines (no fix on the 20.x line) are clean.
	for id := range m {
		if strings.Contains(id, "v22.23.4") || strings.HasSuffix(id, "/opt/new/bin/node") || strings.HasSuffix(id, "/opt/old/bin/node") {
			t.Errorf("unexpected finding %s", id)
		}
	}
	// 24.21.0: the 24/26 CVEs, fixed in 24.22.1.
	if f, ok := m["upstream:node-cve:CVE-2026-105483:/opt/node-v24.21.0-linux-x64/bin/node"]; !ok || f.FixedIn != "24.22.1" ||
		!strings.Contains(f.Remediation, "https://nodejs.org/dist/v24.22.1/") {
		t.Errorf("24.21.0 finding = %+v", f)
	}
	// 26.12.0: all ten October CVEs, fixed in 26.12.1.
	n26 := 0
	for id, f := range m {
		if strings.HasSuffix(id, ":/opt/app/bin/node") {
			n26++
			if f.FixedIn != "26.12.1" {
				t.Errorf("%s fixed_in %s", id, f.FixedIn)
			}
		}
	}
	if n26 != 10 {
		t.Errorf("26.12.0: %d findings, want 10", n26)
	}
	// One NVD question per CVE, not per install.
	seen := map[string]bool{}
	for _, id := range asked {
		if seen[id] {
			t.Errorf("enricher asked twice for %s", id)
		}
		seen[id] = true
	}
}

func TestNodeReleaseDayGap(t *testing.T) {
	// index.json already marks 22.23.4 security; the security-wg list only
	// has the July entries.
	srv := newNodeServer(t, "node-security-wg-gap.json")
	n := srv.provider(t)
	n.Fetch(context.Background())
	fx := newFixture(t)
	installs := []Install{
		{Runtime: "node", Path: "/opt/a/bin/node", Version: "22.23.3", Via: "tarball"},
		{Runtime: "node", Path: "/opt/b/bin/node", Version: "22.22.0", Via: "tarball"},
		{Runtime: "node", Path: "/opt/c/bin/node", Version: "22.23.4", Via: "tarball"},
	}
	m := byID(n.Match(context.Background(), env(fx, nil, rules.Toggles{}), installs, nil))

	// 22.23.3: no CVE yet, so the release finding is all there is.
	var forA []string
	for id := range m {
		if strings.HasSuffix(id, ":/opt/a/bin/node") {
			forA = append(forA, id)
		}
	}
	if len(forA) != 1 {
		t.Fatalf("22.23.3 findings = %v", forA)
	}
	f := m[CheckNodeRelease+":/opt/a/bin/node"]
	if f.Title != "Node 22.23.3 is behind security release 22.23.4 (2026-10-20)" || f.Severity != finding.SeverityHigh ||
		f.FixedIn != "22.23.4" || f.Category != finding.CategoryCVE || f.CVE != "" || f.Source != "nodejs-release" || f.Package != "node" {
		t.Errorf("release finding = %+v", f)
	}
	// 22.22.0: the July CVEs, plus the release finding for the release the
	// CVE list doesn't describe yet.
	if g, ok := m[CheckNodeRelease+":/opt/b/bin/node"]; !ok || g.FixedIn != "22.23.4" || !strings.Contains(g.Evidence, "release-day gap") {
		t.Errorf("22.22.0 gap finding = %+v", g)
	}
	if _, ok := m["upstream:node-cve:CVE-2026-58043:/opt/b/bin/node"]; !ok {
		t.Error("22.22.0: July CVE missing")
	}
	for id := range m {
		if strings.HasSuffix(id, ":/opt/c/bin/node") {
			t.Errorf("22.23.4 flagged: %s", id)
		}
	}
}

func TestNodeToggles(t *testing.T) {
	srv := newNodeServer(t, "node-security-wg.json")
	n := srv.provider(t)
	n.Fetch(context.Background())
	fx := newFixture(t)
	in := []Install{{Runtime: "node", Path: "/opt/b/bin/node", Version: "22.22.0", Via: "tarball"}}

	got := ids(n.Match(context.Background(), env(fx, nil, rules.Toggles{Disable: []string{CheckNodeCVE}}), in, nil))
	if len(got) != 1 || got[0] != CheckNodeRelease+":/opt/b/bin/node" {
		t.Errorf("CVE check disabled: %v", got)
	}
	if got := n.Match(context.Background(), env(fx, nil, rules.Toggles{Disable: []string{"upstream"}}), in, nil); len(got) != 0 {
		t.Errorf("upstream disabled: %v", ids(got))
	}
	if NodeChecksEnabled(rules.Toggles{Disable: []string{"runtimes"}}) {
		t.Error("NodeChecksEnabled with the runtimes rule disabled")
	}
	if !NodeChecksEnabled(rules.Toggles{Disable: []string{"upstream"}}) {
		t.Error("runtime:eol-node still wants the schedule")
	}
}

func TestNodeFetchOfflineAndCache(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	in := []Install{{Runtime: "node", Path: "/opt/b/bin/node", Version: "22.22.0", Via: "tarball"}}

	// Nothing cached and nothing reachable: failed, no findings, no panic.
	srv := newNodeServer(t, "node-security-wg.json")
	srv.down.Store(true)
	n := srv.provider(t)
	st := n.Fetch(ctx)
	if st.Status != feed.StatusFailed || !strings.Contains(st.Detail, "release index") {
		t.Errorf("offline stat = %+v", st)
	}
	if fs := n.Match(ctx, env(fx, nil, rules.Toggles{}), in, nil); len(fs) != 0 {
		t.Errorf("offline findings: %v", ids(fs))
	}
	if n.EOL() != nil {
		t.Error("offline EOL table should be nil (built-in fallback)")
	}

	// Online: cached; a second scan within MaxAge makes no request.
	srv.down.Store(false)
	clock := fixedNow
	n.Fetcher.now = func() time.Time { return clock }
	if st := n.Fetch(ctx); st.Status != feed.StatusOK || st.Requests != 3 {
		t.Fatalf("online stat = %+v", st)
	}
	before := srv.hits.Load()
	if st := n.Fetch(ctx); st.Requests != 0 || st.CacheHits != 3 || st.Status != feed.StatusOK {
		t.Errorf("fresh cache stat = %+v", st)
	}
	if srv.hits.Load() != before {
		t.Error("fresh cache still hit the network")
	}
	// After MaxAge: conditional requests answered 304.
	clock = clock.Add(2 * time.Hour)
	if st := n.Fetch(ctx); st.Requests != 3 || st.CacheHits != 3 || st.Bytes != 0 || st.Status != feed.StatusOK {
		t.Errorf("revalidate stat = %+v", st)
	}
	// Server down later: the stale copy is used and the source is partial.
	clock = clock.Add(2 * time.Hour)
	srv.down.Store(true)
	st = n.Fetch(ctx)
	if st.Status != feed.StatusPartial || !strings.Contains(st.Detail, "using copy from") {
		t.Errorf("stale stat = %+v", st)
	}
	if fs := n.Match(ctx, env(fx, nil, rules.Toggles{}), in, nil); len(fs) == 0 {
		t.Error("stale cache produced no findings")
	}
}

func TestNodeImageInstalls(t *testing.T) {
	comps := []inventory.Component{
		{Ecosystem: inventory.EcoContainerImage, Name: "node", Version: "22.22.0-alpine", Paths: []string{"docker:api"}},
		{Ecosystem: inventory.EcoContainerImage, Name: "docker.io/library/node", Version: "24.22.1", Paths: []string{"podman:web"}},
		{Ecosystem: inventory.EcoContainerImage, Name: "node", Version: "22"},
		{Ecosystem: inventory.EcoContainerImage, Name: "node", Version: "lts-slim"},
		{Ecosystem: inventory.EcoContainerImage, Name: "nodered/node-red", Version: "4.0.0"},
		{Ecosystem: "npm", Name: "node", Version: "1.0.0"},
	}
	got := NodeImageInstalls(comps)
	if len(got) != 2 || got[0].Path != "image:docker.io/library/node:24.22.1" || got[1].Version != "22.22.0" ||
		got[1].Via != "container" || got[1].Containers[0] != "docker:api" {
		t.Fatalf("NodeImageInstalls = %+v", got)
	}
	srv := newNodeServer(t, "node-security-wg.json")
	n := srv.provider(t)
	n.Fetch(context.Background())
	fs := n.Match(context.Background(), env(newFixture(t), nil, rules.Toggles{}), got, nil)
	f, ok := byID(fs)["upstream:node-cve:CVE-2026-111497:image:node:22.22.0-alpine"]
	if !ok || !strings.Contains(f.Remediation, "node:22.23.4") || !strings.Contains(f.Evidence, "docker:api") {
		t.Errorf("image finding = %+v", f)
	}
}
