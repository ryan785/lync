package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
	"github.com/ryan785/lync/internal/matcher"
)

// One fake server for OSV, NVD and Red Hat.
func fakeAPIs(t *testing.T, nvdHits *[]string, osvDown bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/osv/v1/querybatch":
			if osvDown {
				w.WriteHeader(503)
				return
			}
			var req struct {
				Queries []feed.OSVQuery `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			var res []any
			for _, q := range req.Queries {
				switch q.Package.Name {
				case "openssl":
					res = append(res, map[string]any{"vulns": []any{map[string]string{"id": "RLSA-2026:1", "modified": "m"}}})
				case "pcre2":
					res = append(res, map[string]any{"vulns": []any{map[string]string{"id": "DEBIAN-CVE-2026-0010", "modified": "m"}}})
				default:
					res = append(res, map[string]any{})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": res})
		case r.URL.Path == "/osv/v1/vulns/RLSA-2026:1":
			io.WriteString(w, `{"id":"RLSA-2026:1","upstream":["CVE-2026-0001","CVE-2026-0002"],"summary":"Moderate: openssl update",
			 "affected":[{"package":{"name":"openssl","ecosystem":"Rocky Linux:9"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:3.0.7-28.el9_4"}]}]}]}`)
		case r.URL.Path == "/osv/v1/vulns/DEBIAN-CVE-2026-0010":
			io.WriteString(w, `{"id":"DEBIAN-CVE-2026-0010","upstream":["CVE-2026-0010"],
			 "affected":[{"package":{"name":"pcre2","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"10.42-1+deb12u2"}]}]}]}`)
		case r.URL.Path == "/nvd":
			id := r.URL.Query().Get("cveId")
			*nvdHits = append(*nvdHits, id)
			fmt.Fprintf(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":%q,"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.1,"baseSeverity":"CRITICAL"}}]}}}]}`, id)
		case strings.HasPrefix(r.URL.Path, "/rh/"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/rh/"), ".json")
			if id != "CVE-2026-0001" {
				w.WriteHeader(404)
				return
			}
			io.WriteString(w, `{"name":"CVE-2026-0001","threat_severity":"Important","cvss3":{"cvss3_base_score":"7.5"},
			 "affected_release":[{"product_name":"Red Hat Enterprise Linux 9","package":"openssl-1:3.0.7-28.el9_4","advisory":"RHSA-2026:1","cpe":"cpe:/o:redhat:enterprise_linux:9"}]}`)
		default:
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(404)
		}
	}))
}

func newClient(t *testing.T, srv *httptest.Server) *Client {
	dir := t.TempDir()
	return New(Config{CacheDir: dir, OSV: true, NVD: true, RedHat: true,
		OSVURL: srv.URL + "/osv", NVDURL: srv.URL + "/nvd", RedHatURL: srv.URL + "/rh/%s.json"}, dir+"/rh", nil)
}

func TestScanRocky(t *testing.T) {
	var nvd []string
	srv := fakeAPIs(t, &nvd, false)
	defer srv.Close()
	c := newClient(t, srv)
	facts := &collector.Facts{OS: collector.OSInfo{ID: "rocky", VersionID: "9.3", IDLike: []string{"rhel"}},
		Packages: []collector.Package{
			{Name: "openssl-libs", Epoch: 1, Version: "3.0.7", Release: "24.el9", Source: "openssl-3.0.7-24.el9.src.rpm", Manager: "rpm"},
			{Name: "bash", Version: "5.1.8", Release: "9.el9", Source: "bash-5.1.8-9.el9.src.rpm", Manager: "rpm"},
		}}
	r := c.Scan(context.Background(), facts)
	if !r.Sources.Complete {
		t.Fatalf("incomplete: %v", r.Sources.IncompleteReasons)
	}
	fs := matcher.EnrichSeverity(matcher.Match(facts, r.Vulns, nil), r.Vulns)
	if len(fs) != 2 {
		t.Fatalf("findings = %+v", fs)
	}
	for _, f := range fs {
		if f.Package != "openssl-libs" || f.FixedIn != "1:3.0.7-28.el9_4" {
			t.Errorf("finding %+v", f)
		}
		switch f.CVE {
		case "CVE-2026-0001": // Red Hat beats OSV: Important -> High
			if f.Source != "redhat" || f.Severity != finding.SeverityHigh || f.CVSS != 7.5 {
				t.Errorf("CVE-0001: %+v", f)
			}
		case "CVE-2026-0002": // OSV "Moderate", CVSS from NVD
			if f.Severity != finding.SeverityMedium || f.CVSS != 9.1 {
				t.Errorf("CVE-0002: %+v", f)
			}
		}
	}
	// NVD is asked only about the CVE nothing else scored.
	if len(nvd) != 1 || nvd[0] != "CVE-2026-0002" {
		t.Errorf("nvd lookups = %v", nvd)
	}
	names := map[string]string{}
	for _, s := range r.Sources.Sources {
		names[s.Name] = s.Status
	}
	if names["osv"] != "ok" || names["redhat"] != "ok" || names["nvd"] != "ok" || r.Sources.Ecosystem != "Rocky Linux:9" || r.Sources.PackagesChecked != 2 {
		t.Errorf("sources = %+v", r.Sources)
	}
}

func TestScanOSVDownIsIncomplete(t *testing.T) {
	var nvd []string
	srv := fakeAPIs(t, &nvd, true)
	defer srv.Close()
	c := newClient(t, srv)
	facts := &collector.Facts{OS: collector.OSInfo{ID: "debian", VersionID: "12"},
		Packages: []collector.Package{{Name: "libpcre2-8-0:amd64", Version: "10.42-1", Source: "pcre2", Manager: "dpkg"}}}
	r := c.Scan(context.Background(), facts)
	if r.Sources.Complete || len(r.Sources.IncompleteReasons) == 0 || len(r.Vulns) != 0 {
		t.Errorf("want incomplete, got %+v", r.Sources)
	}
	if got := r.Sources.FailedSources(); len(got) != 1 || got[0] != "osv" {
		t.Errorf("failed sources = %v", got)
	}
}

func TestScanUnsupportedDistroIsIncomplete(t *testing.T) {
	c := New(Config{CacheDir: t.TempDir(), OSV: true}, t.TempDir(), nil)
	r := c.Scan(context.Background(), &collector.Facts{OS: collector.OSInfo{ID: "fedora", VersionID: "40"}})
	if r.Sources.Complete || !strings.Contains(strings.Join(r.Sources.IncompleteReasons, " "), "no OSV ecosystem") {
		t.Errorf("sources = %+v", r.Sources)
	}
}

func TestCVELookupDebian(t *testing.T) {
	var nvd []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/osv/v1/vulns/CVE-2026-0010":
			io.WriteString(w, `{"id":"CVE-2026-0010","affected":[]}`)
		case "/osv/v1/vulns/DEBIAN-CVE-2026-0010":
			io.WriteString(w, `{"id":"DEBIAN-CVE-2026-0010","upstream":["CVE-2026-0010"],
			 "affected":[{"package":{"name":"pcre2","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"10.42-1+deb12u2"}]}]}]}`)
		case "/nvd":
			nvd = append(nvd, r.URL.Query().Get("cveId"))
			io.WriteString(w, `{"totalResults":0,"vulnerabilities":[]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c := newClient(t, srv)
	facts := &collector.Facts{OS: collector.OSInfo{ID: "debian", VersionID: "12"},
		Packages: []collector.Package{{Name: "libpcre2-8-0:amd64", Version: "10.42-1", Source: "pcre2", Manager: "dpkg"}}}
	vs, src := c.CVE(context.Background(), facts, "CVE-2026-0010")
	if !src.Complete || len(vs) != 1 || len(nvd) != 1 {
		t.Fatalf("vulns=%+v src=%+v nvd=%v", vs, src, nvd)
	}
	if fs := matcher.Match(facts, vs, nil); len(fs) != 1 || fs[0].FixedIn != "10.42-1+deb12u2" {
		t.Errorf("findings = %+v", fs)
	}
}

func TestParseUpdateinfo(t *testing.T) {
	out := "RLSA-2024:3501 Important/Sec. nghttp2-libs-1.43.0-5.el9_4.3.x86_64\nRLSA-2026:1200 Moderate/Sec.  openssl-libs-1:3.0.7-28.el9_4.x86_64\ngarbage line\n"
	ups := ParseUpdateinfo(out)
	if len(ups) != 2 || ups[0].Package != "nghttp2-libs" || ups[0].Version != "1.43.0-5.el9_4.3" || ups[0].Severity != "Important" ||
		ups[1].Package != "openssl-libs" || ups[1].Version != "1:3.0.7-28.el9_4" || ups[1].Advisory != "RLSA-2026:1200" {
		t.Errorf("ups = %+v", ups)
	}
}

func TestParseAptSimulate(t *testing.T) {
	out := `NOTE: This is only a simulation!
Inst libssl3 [3.0.15-1~deb12u1] (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])
Inst tzdata [2024a-0+deb12u1] (2025b-0+deb12u1 Debian:12.11/stable [all])
Inst libfoo:amd64 [1.0-1] (1.0-1ubuntu0.1 Ubuntu:22.04/jammy-security [amd64])
Inst newpkg (1.0 Debian:12/stable [amd64])
Conf libssl3 (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])`
	ups := ParseAptSimulate(out)
	if len(ups) != 2 || ups[0].Package != "libssl3" || ups[0].Version != "3.0.17-1~deb12u2" || ups[1].Package != "libfoo" {
		t.Errorf("ups = %+v", ups)
	}
}

func TestCrossCheck(t *testing.T) {
	facts := &collector.Facts{Packages: []collector.Package{
		{Name: "libssl3:amd64", Version: "3.0.15-1~deb12u1", Source: "openssl", Manager: "dpkg"},
		{Name: "openssl", Version: "3.0.15-1~deb12u1", Source: "openssl", Manager: "dpkg"},
		{Name: "libpcre2-8-0:amd64", Version: "10.42-1", Source: "pcre2", Manager: "dpkg"},
		{Name: "curl", Version: "7.88.1-10", Source: "curl", Manager: "dpkg"},
	}}
	fs := []finding.Finding{
		{ID: "CVE-1:libssl3:amd64", Category: finding.CategoryCVE, CVE: "CVE-1", Package: "libssl3:amd64", FixedIn: "3.0.17-1~deb12u2"},
		{ID: "CVE-2:libpcre2-8-0:amd64", Category: finding.CategoryCVE, CVE: "CVE-2", Package: "libpcre2-8-0:amd64", FixedIn: "10.42-1+deb12u2"},
		{ID: "ssh:x", Category: finding.CategoryConfig},
	}
	ups := []PendingUpdate{{Package: "openssl", Version: "3.0.17-1~deb12u2"}, {Package: "curl", Version: "7.88.1-10+deb12u12", Origin: "Debian-Security:12/stable-security"}}
	out, summary := CrossCheck(facts, fs, ups, "apt")
	if !strings.Contains(out[0].Evidence, "security update openssl") {
		t.Errorf("same-source update should confirm: %q", out[0].Evidence)
	}
	if !strings.Contains(out[1].Evidence, "shows no pending security update") {
		t.Errorf("discrepancy not flagged: %q", out[1].Evidence)
	}
	if len(out) != 4 || out[3].ID != "pkgmgr:security-update:curl" || out[3].Remediation != "apt-get install --only-upgrade curl" || out[3].FixedIn != "7.88.1-10+deb12u12" {
		t.Errorf("extra findings = %+v", out[3:])
	}
	if summary != "pending=2 confirmed=1 lookup_only=1 pkgmgr_only=1" {
		t.Errorf("summary = %q", summary)
	}
}

func TestLocalCheckRunners(t *testing.T) {
	calls := []string{}
	run := func(_ context.Context, _ time.Duration, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "dnf" && args[0] == "--version" {
			return []byte("4.14"), nil
		}
		if name == "dnf" {
			return []byte("RLSA-2026:1 Important/Sec. openssl-libs-1:3.0.7-28.el9_4.x86_64\n"), nil
		}
		return nil, fmt.Errorf("unexpected")
	}
	ups, st := LocalCheck(context.Background(), run, "rpm", false)
	if len(ups) != 1 || st.Status != "ok" || st.Name != "dnf" {
		t.Errorf("ups=%+v st=%+v", ups, st)
	}
	if calls[len(calls)-1] != "dnf -C -q updateinfo list --security" {
		t.Errorf("calls = %v (must be cache-only, no refresh)", calls)
	}
	calls = nil
	LocalCheck(context.Background(), run, "rpm", true)
	if len(calls) != 3 || calls[1] != "dnf -q makecache" {
		t.Errorf("refresh calls = %v", calls)
	}
	if _, st := LocalCheck(context.Background(), run, "apk", false); st.Status != "skipped" {
		t.Errorf("apk: %+v", st)
	}
}
