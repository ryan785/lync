package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryan785/lync/internal/collector"
)

func TestCVSS3BaseScore(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H": 5.5,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L": 7.6,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for v, want := range cases {
		got, ok := CVSS3BaseScore(v)
		if !ok || got != want {
			t.Errorf("CVSS3BaseScore(%s) = %v,%v want %v", v, got, ok, want)
		}
	}
	for _, bad := range []string{"", "CVSS:2.0/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV:N/AC:L"} {
		if _, ok := CVSS3BaseScore(bad); ok {
			t.Errorf("CVSS3BaseScore(%q) should fail", bad)
		}
	}
}

func TestEcosystemForOS(t *testing.T) {
	cases := []struct {
		os           collector.OSInfo
		query, distr string
		ok           bool
	}{
		{collector.OSInfo{ID: "rocky", VersionID: "9.4"}, "Rocky Linux:9", "rhel:9", true},
		{collector.OSInfo{ID: "almalinux", VersionID: "8.10"}, "AlmaLinux:8", "rhel:8", true},
		{collector.OSInfo{ID: "rhel", VersionID: "9.2"}, "Red Hat:enterprise_linux:9::baseos", "rhel:9", true},
		{collector.OSInfo{ID: "debian", VersionID: "12"}, "Debian:12", "debian:12", true},
		{collector.OSInfo{ID: "ubuntu", VersionID: "22.04", Version: "22.04.4 LTS (Jammy Jellyfish)"}, "Ubuntu:22.04:LTS", "ubuntu:22.04", true},
		{collector.OSInfo{ID: "ubuntu", VersionID: "24.10", Version: "24.10 (Oracular Oriole)"}, "Ubuntu:24.10", "ubuntu:24.10", true},
		{collector.OSInfo{ID: "alpine", VersionID: "3.19.1"}, "Alpine:v3.19", "alpine:3.19", true},
		{collector.OSInfo{ID: "fedora", VersionID: "40"}, "", "", false},
	}
	for _, c := range cases {
		e, ok := EcosystemForOS(c.os)
		if ok != c.ok || (ok && (e.Query[0] != c.query || e.Distro != c.distr)) {
			t.Errorf("%s %s: got %+v ok=%v", c.os.ID, c.os.VersionID, e, ok)
		}
	}
	u, _ := EcosystemForOS(collector.OSInfo{ID: "ubuntu", VersionID: "22.04", Version: "22.04 LTS"})
	if !u.Accept("Ubuntu:22.04:LTS") || !u.Accept("Ubuntu:22.04") || u.Accept("Ubuntu:Pro:22.04:LTS") || u.Accept("Ubuntu:20.04:LTS") {
		t.Error("ubuntu Accept wrong")
	}
	r, _ := EcosystemForOS(collector.OSInfo{ID: "rhel", VersionID: "9.2"})
	if !r.Accept("Red Hat:enterprise_linux:9::appstream") || r.Accept("Red Hat:enterprise_linux:8::appstream") || r.Accept("Red Hat:rhel_eus:9.2::baseos") {
		t.Error("rhel Accept wrong")
	}
}

func TestOSVQueries(t *testing.T) {
	names, ver := osvQueries(collector.Package{Name: "openssl-libs", Epoch: 1, Version: "3.0.7", Release: "24.el9", Source: "openssl-3.0.7-24.el9.src.rpm", Manager: "rpm"})
	if ver != "1:3.0.7-24.el9" || len(names) != 2 || names[0] != "openssl-libs" || names[1] != "openssl" {
		t.Errorf("rpm: %v %q", names, ver)
	}
	names, ver = osvQueries(collector.Package{Name: "libssl3:amd64", Version: "3.0.15-1~deb12u1+b1", SourceVersion: "3.0.15-1~deb12u1", Source: "openssl", Manager: "dpkg"})
	if ver != "3.0.15-1~deb12u1" || len(names) != 1 || names[0] != "openssl" {
		t.Errorf("dpkg: %v %q", names, ver)
	}
	names, _ = osvQueries(collector.Package{Name: "libcrypto3", Version: "3.1.4-r0", Source: "openssl", Manager: "apk"})
	if names[0] != "openssl" {
		t.Errorf("apk: %v", names)
	}
}

const debianRecord = `{
 "id": "DEBIAN-CVE-2026-0001", "upstream": ["CVE-2026-0001"], "modified": "2026-10-01T00:00:00Z",
 "details": "pcre2 overflow",
 "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
 "affected": [
  {"package": {"name": "pcre2", "ecosystem": "Debian:12"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "10.42-1+deb12u2"}]}], "ecosystem_specific": {"urgency": "not yet assigned"}},
  {"package": {"name": "pcre2", "ecosystem": "Debian:13"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "10.46-1"}]}]}
 ]}`

const unfixedRecord = `{"id": "DEBIAN-CVE-2026-0002", "upstream": ["CVE-2026-0002"], "affected": [
  {"package": {"name": "pcre2", "ecosystem": "Debian:12"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}`

type fakeOSV struct {
	mu       sync.Mutex
	batches  int
	details  map[string]int
	fail     bool
	modified string
}

func (f *fakeOSV) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.fail {
			w.WriteHeader(400)
			return
		}
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/querybatch":
			f.batches++
			var req struct {
				Queries []OSVQuery `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			var results []any
			for _, q := range req.Queries {
				switch {
				case q.Package.Name == "pcre2" && q.Version == "10.42-1" && q.PageToken == "":
					results = append(results, map[string]any{
						"vulns":           []any{map[string]string{"id": "DEBIAN-CVE-2026-0001", "modified": f.modified}},
						"next_page_token": "p2"})
				case q.Package.Name == "pcre2" && q.PageToken == "p2":
					results = append(results, map[string]any{"vulns": []any{
						map[string]string{"id": "DEBIAN-CVE-2026-0002", "modified": "2026-01-01T00:00:00Z"},
						map[string]string{"id": "DEBIAN-CVE-2026-0001", "modified": f.modified}}})
				default:
					results = append(results, map[string]any{})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			f.details[id]++
			switch id {
			case "DEBIAN-CVE-2026-0001":
				io.WriteString(w, debianRecord)
			case "DEBIAN-CVE-2026-0002":
				io.WriteString(w, unfixedRecord)
			default:
				w.WriteHeader(404)
			}
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
}

func debianPkgs() []collector.Package {
	return []collector.Package{
		{Name: "libpcre2-8-0:amd64", Version: "10.42-1", Source: "pcre2", Manager: "dpkg"},
		{Name: "libpcre2-16-0:amd64", Version: "10.42-1", Source: "pcre2", Manager: "dpkg"},
		{Name: "bash", Version: "5.2.15-2+b7", Source: "bash", SourceVersion: "5.2.15-2", Manager: "dpkg"},
	}
}

func TestOSVLookupScan(t *testing.T) {
	f := &fakeOSV{details: map[string]int{}, modified: "2026-10-01T00:00:00Z"}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	dir := t.TempDir()
	o := NewOSVLookup(filepath.Join(dir, "osv.json"))
	o.BaseURL = srv.URL
	eco, _ := EcosystemForOS(collector.OSInfo{ID: "debian", VersionID: "12"})

	r := o.Scan(context.Background(), eco, debianPkgs())
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if r.PackagesChecked != 3 || r.Advisories != 2 {
		t.Errorf("checked=%d advisories=%d", r.PackagesChecked, r.Advisories)
	}
	if f.batches != 2 {
		t.Errorf("batches = %d, want 2 (first page + next_page_token)", f.batches)
	}
	if f.details["DEBIAN-CVE-2026-0001"] != 1 {
		t.Errorf("detail fetched %d times, want 1 (deduped across queries/pages)", f.details["DEBIAN-CVE-2026-0001"])
	}
	var fixed, unfixed *Vulnerability
	for i := range r.Vulns {
		switch r.Vulns[i].ID {
		case "CVE-2026-0001":
			fixed = &r.Vulns[i]
		case "CVE-2026-0002":
			unfixed = &r.Vulns[i]
		}
	}
	if fixed == nil || fixed.CVSS != 9.8 || len(fixed.Affects) != 1 || fixed.Affects[0].Distro != "debian:12" ||
		fixed.Affects[0].FixedVersion != "10.42-1+deb12u2" || fixed.Affects[0].Name != "pcre2" {
		t.Errorf("fixed vuln = %+v", fixed)
	}
	if unfixed == nil || unfixed.Affects[0].Status != "unfixed" || unfixed.Affects[0].FixedVersion != "" {
		t.Errorf("unfixed vuln = %+v", unfixed)
	}
	if r.Stat.Requests != 4 || r.Stat.Bytes == 0 {
		t.Errorf("stat = %+v", r.Stat)
	}

	// Second scan: details come from the cache while "modified" is unchanged.
	r2 := o.Scan(context.Background(), eco, debianPkgs())
	if f.details["DEBIAN-CVE-2026-0001"] != 1 || r2.Stat.CacheHits != 2 || len(r2.Vulns) != len(r.Vulns) {
		t.Errorf("cache not used: details=%v hits=%d", f.details, r2.Stat.CacheHits)
	}
	// A changed modified stamp refetches.
	f.modified = "2026-10-20T00:00:00Z"
	o.Scan(context.Background(), eco, debianPkgs())
	if f.details["DEBIAN-CVE-2026-0001"] != 2 {
		t.Errorf("modified advisory not refetched: %v", f.details)
	}
	if fi, err := os.Stat(filepath.Join(dir, "osv.json")); err != nil || fi.Size() > 10000 {
		t.Errorf("cache file: %v %v", fi, err)
	}

	// The API failing makes the result incomplete, never "0 findings".
	f.fail = true
	r3 := o.Scan(context.Background(), eco, debianPkgs())
	if r3.Err == nil || r3.Stat.Status != StatusFailed || len(r3.Vulns) != 0 {
		t.Errorf("failure not reported: %+v", r3.Stat)
	}
}

func TestOSVQueryBatchChunks(t *testing.T) {
	var sizes []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []OSVQuery `json:"queries"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		sizes = append(sizes, len(req.Queries))
		res := make([]any, len(req.Queries))
		for i := range res {
			res[i] = map[string]any{}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	}))
	defer srv.Close()
	o := NewOSVLookup("")
	o.BaseURL = srv.URL
	var qs []OSVQuery
	for i := 0; i < 2500; i++ {
		qs = append(qs, OSVQuery{Package: OSVPackage{Name: fmt.Sprintf("p%d", i), Ecosystem: "Debian:12"}, Version: "1"})
	}
	if _, err := o.QueryBatch(context.Background(), qs); err != nil {
		t.Fatal(err)
	}
	if len(sizes) != 3 || sizes[0] != 1000 || sizes[2] != 500 {
		t.Errorf("chunks = %v", sizes)
	}
}

func TestOSVCVELookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/v1/vulns/") {
		case "CVE-2026-0001":
			io.WriteString(w, `{"id":"CVE-2026-0001","related":["DEBIAN-CVE-2026-0001","DSA-9999-1","ALSA-2026:1"],"affected":[]}`)
		case "DEBIAN-CVE-2026-0001":
			io.WriteString(w, debianRecord)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	o := NewOSVLookup("")
	o.BaseURL = srv.URL
	eco, _ := EcosystemForOS(collector.OSInfo{ID: "debian", VersionID: "12"})
	vs, st := o.CVE(context.Background(), eco, "CVE-2026-0001")
	if st.Status != StatusOK || len(vs) == 0 || vs[0].Affects[0].FixedVersion != "10.42-1+deb12u2" {
		t.Errorf("vulns=%+v stat=%+v", vs, st)
	}
	if st.Requests != 3 { // CVE record, DEBIAN-CVE-, DSA- (ALSA- is not Debian's)
		t.Errorf("requests = %d", st.Requests)
	}
}

func TestNVDLookupRateLimitCapCache(t *testing.T) {
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("cveId")
		hits = append(hits, id)
		if r.Header.Get("apiKey") != "" {
			t.Error("no key configured, but apiKey header sent")
		}
		if id == "CVE-2026-0404" {
			io.WriteString(w, `{"totalResults":0,"vulnerabilities":[]}`)
			return
		}
		fmt.Fprintf(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":%q,"descriptions":[{"lang":"en","value":"x"}],
		 "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}}]}}}]}`, id)
	}))
	defer srv.Close()
	dir := t.TempDir()
	n := NewNVDLookup("", filepath.Join(dir, "nvd.json"))
	n.BaseURL = srv.URL
	n.Max = 7
	clock := time.Unix(1_000_000, 0)
	var slept []time.Duration
	n.now = func() time.Time { return clock }
	n.sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		clock = clock.Add(d)
		return nil
	}

	var ids []string
	for i := 1; i <= 9; i++ {
		ids = append(ids, fmt.Sprintf("CVE-2026-%04d", i))
	}
	ids[0] = "CVE-2026-0404"
	vs, st := n.Lookup(context.Background(), ids)
	if len(hits) != 7 || st.Requests != 7 {
		t.Errorf("requests = %d (hits %v), want cap 7", st.Requests, hits)
	}
	if len(slept) != 1 { // 5 per 30 s: request 6 waits for the window to roll; 7 then fits
		t.Errorf("rate limiter slept %v", slept)
	}
	if len(vs) != 6 || vs[0].CVSS != 7.5 || vs[0].Severity != "HIGH" {
		t.Errorf("vulns = %d %+v", len(vs), vs)
	}
	if !strings.Contains(st.Detail, "2 CVE(s) not looked up") || st.Status != StatusOK {
		t.Errorf("stat = %+v", st)
	}
	// Second run: 7 cached (incl. the negative answer), 2 fetched.
	hits = nil
	_, st2 := n.Lookup(context.Background(), ids)
	if st2.CacheHits != 7 || len(hits) != 2 {
		t.Errorf("second run hits=%d cache=%d", len(hits), st2.CacheHits)
	}
}

const rhDetail = `{"name":"CVE-2026-0003","threat_severity":"Important","public_date":"2026-05-01T00:00:00Z",
 "bugzilla":{"description":"openssl: bug"},"cvss3":{"cvss3_base_score":"7.5"},
 "affected_release":[
  {"product_name":"Red Hat Enterprise Linux 9","package":"openssl-1:3.0.7-28.el9_4","advisory":"RHSA-2026:1","cpe":"cpe:/o:redhat:enterprise_linux:9"},
  {"product_name":"Red Hat Enterprise Linux 9.2 Extended Update Support","package":"openssl-1:3.0.7-20.el9_2","advisory":"RHSA-2026:2","cpe":"cpe:/o:redhat:rhel_eus:9.2"},
  {"product_name":"Red Hat Enterprise Linux 8","package":"php:8.0-8100020240327101215.489197e6","advisory":"RHSA-2026:3","cpe":"cpe:/a:redhat:enterprise_linux:8::appstream"},
  {"product_name":"Red Hat OpenShift","package":"foo-1-1","advisory":"RHSA-2026:4","cpe":"cpe:/a:redhat:openshift:4"}],
 "package_state":[{"product_name":"Red Hat Enterprise Linux 8","package_name":"openssl","fix_state":"Not affected"}]}`

func TestRedHatDetailsAndVuln(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if strings.Contains(r.URL.Path, "CVE-2026-0003") {
			io.WriteString(w, rhDetail)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	dir := t.TempDir()
	d := NewRedHatDetails(dir)
	d.URL = srv.URL + "/cve/%s.json"
	det, cached, err := d.Get(context.Background(), "CVE-2026-0003")
	if err != nil || det == nil || cached {
		t.Fatalf("get: %v %v %v", det, cached, err)
	}
	if len(det.AffectedRelease) != 3 { // OpenShift dropped from the cache
		t.Errorf("affected_release = %d", len(det.AffectedRelease))
	}
	if _, cached, _ = d.Get(context.Background(), "CVE-2026-0003"); !cached || n != 1 {
		t.Errorf("second Get should hit the cache (requests %d)", n)
	}
	if det, _, err := d.Get(context.Background(), "CVE-2026-0999"); det != nil || err != nil {
		t.Errorf("404 should be (nil, nil), got %v %v", det, err)
	}
	v := RedHatDetailToVuln("CVE-2026-0003", det, "9")
	if v.Severity != "Important" || v.CVSS != 7.5 || v.Source != "redhat" {
		t.Errorf("vuln = %+v", v)
	}
	if len(v.Affects) != 1 || v.Affects[0].FixedVersion != "1:3.0.7-28.el9_4" || v.Affects[0].Distro != "rhel:9" {
		t.Errorf("affects = %+v (EUS and module NSVC must be skipped)", v.Affects)
	}
}

func TestOSVSeverityLabels(t *testing.T) {
	r := &osvRecord{ID: "RLSA-2026:1", Upstream: []string{"CVE-2026-1", "CVE-2026-2"}, Summary: "Important: openssl security update",
		Affected: []osvAffected{{Package: osvPackage{Name: "openssl", Ecosystem: "Rocky Linux:9"},
			Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "0"}, {Fixed: "1:3.0.7-28.el9_4"}}}}}}}
	vs := osvToVulns(r, nil, "rhel:9", false)
	if len(vs) != 2 || vs[0].Severity != "Important" || vs[1].ID != "CVE-2026-2" {
		t.Errorf("rocky: %+v", vs)
	}
	u := &osvRecord{ID: "UBUNTU-CVE-2026-3", Upstream: []string{"CVE-2026-3"},
		Severity: []osvSeverity{{Type: "Ubuntu", Score: "negligible"}},
		Affected: []osvAffected{{Package: osvPackage{Name: "x", Ecosystem: "Ubuntu:22.04:LTS"}, Ranges: []osvRange{{Events: []osvEvent{{Fixed: "1"}}}}}}}
	if vs := osvToVulns(u, nil, "ubuntu:22.04", false); vs[0].Severity != "Low" {
		t.Errorf("ubuntu negligible -> %q", vs[0].Severity)
	}
}
