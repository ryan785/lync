package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryan785/lync/internal/finding"
)

// fakeOSV serves /v1/querybatch and /v1/vulns/{id} from fixed data.
type fakeOSV struct {
	mu        sync.Mutex
	batches   [][]osvQuery
	detailGET map[string]int
	vulns     map[string]string // id -> record JSON
	hits      map[string][]string
	paged     map[string]bool // name -> split its hits over two pages
}

func (f *fakeOSV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
		var req struct {
			Queries []osvQuery `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		f.batches = append(f.batches, req.Queries)
		type vuln struct {
			ID string `json:"id"`
		}
		type res struct {
			Vulns []vuln `json:"vulns,omitempty"`
			Next  string `json:"next_page_token,omitempty"`
		}
		var out struct {
			Results []res `json:"results"`
		}
		for _, q := range req.Queries {
			ids := f.hits[q.Package.Ecosystem+"/"+q.Package.Name+"@"+q.Version]
			var rr res
			if f.paged[q.Package.Name] && len(ids) > 1 {
				if q.PageToken == "" {
					ids, rr.Next = ids[:1], "page2"
				} else {
					ids = ids[1:]
				}
			}
			for _, id := range ids {
				rr.Vulns = append(rr.Vulns, vuln{ID: id})
			}
			out.Results = append(out.Results, rr)
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		f.detailGET[id]++
		body, ok := f.vulns[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	default:
		http.NotFound(w, r)
	}
}

const ghsaLodash = `{"id":"GHSA-p6mc-m468-83gw","summary":"Prototype Pollution in lodash","aliases":["CVE-2020-8203"],
 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"}],
 "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"3.7.0"},{"fixed":"4.17.19"}]}]}],
 "references":[{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2020-8203"}],
 "database_specific":{"severity":"HIGH"}}`

const ghsaLodash2 = `{"id":"GHSA-35jh-r3h4-6jhm","summary":"Command Injection in lodash","aliases":["CVE-2021-23337"],
 "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}],
 "database_specific":{"severity":"HIGH"}}`

const pysecURLLib = `{"id":"PYSEC-2019-133","aliases":["CVE-2019-11324","GHSA-mh33-7rrq-662w"],
 "affected":[{"package":{"ecosystem":"PyPI","name":"urllib3"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.24.2"}]}]}]}`

const ghsaURLLib = `{"id":"GHSA-mh33-7rrq-662w","aliases":["CVE-2019-11324","PYSEC-2019-133"],
 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
 "affected":[{"package":{"ecosystem":"PyPI","name":"urllib3"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.24.2"}]}]}],
 "database_specific":{"severity":"HIGH"}}`

const ghsaLog4j = `{"id":"GHSA-jfh8-c2jp-5v3q","aliases":["CVE-2021-44228"],
 "affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},
   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.13.0"},{"fixed":"2.15.0"}]},
             {"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.3.1"}]},
             {"type":"ECOSYSTEM","events":[{"introduced":"2.4"},{"fixed":"2.12.2"}]}]}],
 "database_specific":{"severity":"CRITICAL"}}`

func newFakeOSV() *fakeOSV {
	return &fakeOSV{
		detailGET: map[string]int{},
		vulns: map[string]string{
			"GHSA-p6mc-m468-83gw": ghsaLodash, "GHSA-35jh-r3h4-6jhm": ghsaLodash2,
			"PYSEC-2019-133": pysecURLLib, "GHSA-mh33-7rrq-662w": ghsaURLLib,
			"GHSA-jfh8-c2jp-5v3q": ghsaLog4j,
		},
		hits: map[string][]string{
			"npm/lodash@4.17.15":                               {"GHSA-p6mc-m468-83gw", "GHSA-35jh-r3h4-6jhm"},
			"PyPI/urllib3@1.24.1":                              {"PYSEC-2019-133", "GHSA-mh33-7rrq-662w"},
			"Maven/org.apache.logging.log4j:log4j-core@2.14.1": {"GHSA-jfh8-c2jp-5v3q"},
		},
		paged: map[string]bool{"lodash": true},
	}
}

var testComps = []Component{
	{Ecosystem: EcoNPM, Name: "lodash", Version: "4.17.15", Paths: []string{"/var/www/shop/package-lock.json"}, Source: SourceLockfile, Scope: ScopeApp},
	{Ecosystem: EcoNPM, Name: "express", Version: "4.18.2", Paths: []string{"/var/www/shop/package-lock.json"}, Source: SourceLockfile, Scope: ScopeApp},
	{Ecosystem: EcoPyPI, Name: "urllib3", Version: "1.24.1", Paths: []string{"/srv/api/requirements.txt", "/srv/api/venv/lib/python3.11/site-packages/urllib3-1.24.1.dist-info"}, Source: SourceManifest, Scope: ScopeApp},
	{Ecosystem: EcoMaven, Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", Paths: []string{"/opt/app/app.war!WEB-INF/lib/log4j-core-2.14.1.jar"}, Source: SourceManifest, Scope: ScopeApp},
	{Ecosystem: EcoWordPress, Name: "wordpress", Version: "5.8.1", Paths: []string{"/var/www/html/wp-includes/version.php"}},
	{Ecosystem: EcoMaven, Name: "in-house-util", Version: "1.0.0", Paths: []string{"/opt/x.jar"}},
}

func TestQueryOSV(t *testing.T) {
	fake := newFakeOSV()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	hits, err := QueryOSV(context.Background(), &OSVClient{BaseURL: srv.URL, BatchSize: 2, HTTP: srv.Client()}, testComps)
	if err != nil {
		t.Fatal(err)
	}
	// Batch 1 (lodash, express), its page-2 round for lodash only, then batch 2.
	if len(fake.batches) != 3 || len(fake.batches[0]) != 2 || len(fake.batches[1]) != 1 || len(fake.batches[2]) != 2 {
		t.Fatalf("batches = %v", fake.batches)
	}
	if fake.batches[1][0].PageToken != "page2" || fake.batches[1][0].Package.Name != "lodash" {
		t.Errorf("page-2 query = %+v", fake.batches[1][0])
	}
	for _, b := range fake.batches {
		for _, q := range b {
			if q.Package.Ecosystem == EcoWordPress || q.Package.Name == "in-house-util" {
				t.Errorf("unqueryable component sent: %+v", q)
			}
		}
	}
	if len(fake.detailGET) != 5 {
		t.Errorf("detail fetches = %v (want one per distinct hit id)", fake.detailGET)
	}
	for id, n := range fake.detailGET {
		if n != 1 {
			t.Errorf("%s fetched %d times", id, n)
		}
	}
	if len(hits) != 5 {
		t.Fatalf("hits = %d", len(hits))
	}

	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	fs := Findings(hits, now)
	byID := map[string]finding.Finding{}
	for _, f := range fs {
		byID[f.ID] = f
		if f.Category != finding.CategoryCVE || f.Source != "osv" || f.DetectedAt != now || f.Evidence == "" || f.Remediation == "" || len(f.References) == 0 {
			t.Errorf("shape: %+v", f)
		}
	}
	// lodash: two CVEs; urllib3: GHSA+PYSEC collapse into one CVE per path (2 paths); log4j: 1.
	if len(fs) != 5 {
		var ids []string
		for _, f := range fs {
			ids = append(ids, f.ID)
		}
		t.Fatalf("findings = %v", ids)
	}
	l := byID["CVE-2020-8203:npm/lodash@/var/www/shop/package-lock.json"]
	if l.CVE != "CVE-2020-8203" || l.FixedIn != "4.17.19" || l.Severity != finding.SeverityHigh || l.CVSS != 7.4 {
		t.Errorf("lodash finding = %+v", l)
	}
	if !strings.Contains(l.Remediation, "upgrade lodash to >= 4.17.19 in /var/www/shop") || !strings.Contains(l.Remediation, "npm install lodash@4.17.19") {
		t.Errorf("lodash remediation = %q", l.Remediation)
	}
	if !strings.Contains(l.Evidence, "path: /var/www/shop/package-lock.json") || !strings.Contains(l.Evidence, "installed: lodash 4.17.15") {
		t.Errorf("lodash evidence = %q", l.Evidence)
	}
	u := byID["CVE-2019-11324:PyPI/urllib3@/srv/api/requirements.txt"]
	if u.FixedIn != "1.24.2" || u.Severity != finding.SeverityHigh || !strings.Contains(u.Evidence, "PYSEC-2019-133") {
		t.Errorf("urllib3 finding = %+v", u)
	}
	if !strings.Contains(u.Remediation, "requirements.txt") {
		t.Errorf("urllib3 remediation = %q", u.Remediation)
	}
	v := byID["CVE-2019-11324:PyPI/urllib3@/srv/api/venv/lib/python3.11/site-packages/urllib3-1.24.1.dist-info"]
	if !strings.Contains(v.Remediation, "pip install --upgrade 'urllib3>=1.24.2'") || !strings.Contains(v.Remediation, "/srv/api/venv/lib/python3.11/site-packages") {
		t.Errorf("venv remediation = %q", v.Remediation)
	}
	g := byID["CVE-2021-44228:Maven/org.apache.logging.log4j:log4j-core@/opt/app/app.war!WEB-INF/lib/log4j-core-2.14.1.jar"]
	if g.FixedIn != "2.15.0" || g.Severity != finding.SeverityCritical || !strings.Contains(g.Remediation, "in /opt/app/app.war") {
		t.Errorf("log4j finding = %+v", g)
	}
}

func TestQueryOSVErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadRequest)
	}))
	defer srv.Close()
	if _, err := QueryOSV(context.Background(), &OSVClient{BaseURL: srv.URL}, testComps[:1]); err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("err = %v", err)
	}
	// nothing queryable: no request at all
	hits, err := QueryOSV(context.Background(), &OSVClient{BaseURL: "http://127.0.0.1:1"}, testComps[4:])
	if err != nil || len(hits) != 0 {
		t.Errorf("hits=%v err=%v", hits, err)
	}
}

func TestCVSS3Score(t *testing.T) {
	for vec, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H": 7.4,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N": 5.4,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	} {
		got, ok := CVSS3Score(vec)
		if !ok || got != want {
			t.Errorf("%s = %v,%v want %v", vec, got, ok, want)
		}
	}
	if _, ok := CVSS3Score("CVSS:4.0/AV:N"); ok {
		t.Error("incomplete vector accepted")
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"4.17.15", "4.17.19", -1}, {"4.17.21", "4.17.19", 1}, {"1.0", "1.0.0", 0},
		{"2.0.0-rc1", "2.0.0", -1}, {"2.0a1", "2.0", -1}, {"1.10", "1.9", 1},
		{"v1.2.3", "1.2.3", 0}, {"2.15.0", "2.3.1", 1}, {"1.0.0+build5", "1.0.0", 0},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("Compare(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestRemediationPerEcosystem(t *testing.T) {
	for _, c := range []struct {
		comp Component
		path string
		want string
	}{
		{Component{Ecosystem: EcoNPM, Name: "lodash"}, "/srv/a/yarn.lock", "yarn upgrade lodash@4.17.21"},
		{Component{Ecosystem: EcoNPM, Name: "tar", Scope: ScopeSystem}, "/usr/lib/node_modules/npm/node_modules/tar/package.json", "npm install -g tar@4.17.21"},
		{Component{Ecosystem: EcoPackagist, Name: "guzzlehttp/guzzle"}, "/var/www/shop/composer.lock", "in /var/www/shop (composer update guzzlehttp/guzzle --with-dependencies)"},
		{Component{Ecosystem: EcoGo, Name: "stdlib"}, "/usr/local/bin/tool", "rebuild /usr/local/bin/tool with Go >= 4.17.21"},
		{Component{Ecosystem: EcoCrates, Name: "smallvec"}, "/srv/r/Cargo.lock", "cargo update -p smallvec"},
		{Component{Ecosystem: EcoRubyGems, Name: "rack"}, "/srv/r/Gemfile.lock", "bundle update rack"},
		{Component{Ecosystem: EcoNuGet, Name: "Newtonsoft.Json"}, "/opt/api/Api.deps.json", "dotnet add package Newtonsoft.Json --version 4.17.21"},
		{Component{Ecosystem: EcoPyPI, Name: "jinja2"}, "/srv/p/poetry.lock", "poetry update jinja2"},
		{Component{Ecosystem: EcoMaven, Name: "org.yaml:snakeyaml"}, "/srv/tomcat/webapps/api/META-INF/maven/org.yaml/snakeyaml/pom.properties", "in /srv/tomcat/webapps/api (update"},
	} {
		got := remediation(c.comp, c.path, "4.17.21")
		if !strings.Contains(got, c.want) {
			t.Errorf("%s %s: %q lacks %q", c.comp.Ecosystem, c.path, got, c.want)
		}
	}
}
