package rules

import (
	"io/fs"
	"testing"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

func phpFacts(version, release string) *collector.Facts {
	return &collector.Facts{Packages: []collector.Package{
		{Name: "php-fpm", Version: version, Release: release, Manager: "rpm"},
	}}
}

func TestPHPRuleSystemAndRemi(t *testing.T) {
	fx := newFixture(t)
	fx.file("/etc/passwd", passwdFixture).file("/etc/group", groupFixture).
		// system PHP 8.0 (Rocky appstream), defaults mostly untouched
		file("/etc/php.ini", "[PHP]\nexpose_php = On\ndisplay_errors = Off\nallow_url_include = Off\ndisable_functions =\n").
		file("/etc/php.d/20-hardening.ini", "expose_php = Off ; hide version\n").
		file("/etc/php-fpm.d/www.conf", "[www]\nuser = apache\nlisten = /run/php-fpm/www.sock\nphp_value[session.save_path] = /var/lib/php/session\nphp_admin_flag[display_errors] = on\n").
		dir("/var/lib/php/session").
		meta("/var/lib/php/session", fs.ModeDir|0o770, 0, 0). // root:root 770 -> apache can't write
		// Remi php74 with upload progress explicitly off and url include on
		file("/etc/opt/remi/php74/php.ini", "session.upload_progress.enabled = Off\nallow_url_include = On\ndisable_functions = exec,system\nexpose_php=Off\ndisplay_errors=Off\n").
		file("/etc/opt/remi/php74/php-fpm.d/app.conf", "[global]\npid = x\n[app]\nuser = nginx\nphp_admin_value[cgi.fix_pathinfo] = 0\nphp_value[session.save_path] = /var/opt/remi/php74/lib/php/session\n")

	got := runRule(NewPHPRule(), phpFacts("8.0.30", "1.module+el8.10.0+1872+5d4a5b6c"), fx.opts())
	requireShape(t, got)

	want := map[string]finding.Severity{
		"php:upload-progress:system:www":         finding.SeverityHigh,
		"php:display-errors:system:www":          finding.SeverityMedium, // pool php_admin_flag overrides ini
		"php:cgi-fix-pathinfo:system:www":        finding.SeverityLow,
		"php:disable-functions-empty:system:www": finding.SeverityLow,
		"php:session-path:system:www":            finding.SeverityMedium,
		"php:eol-branch:system":                  finding.SeverityMedium, // distro build caveat
		"php:allow-url-include:remi-php74:app":   finding.SeverityHigh,
		"php:session-path:remi-php74:app":        finding.SeverityMedium, // dir missing
		"php:eol-branch:remi-php74":              finding.SeverityHigh,
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
		"php:expose-php:system:www",           // php.d override wins
		"php:upload-progress:remi-php74:app",  // explicitly Off
		"php:cgi-fix-pathinfo:remi-php74:app", // pool sets 0
		"php:disable-functions-empty:remi-php74:app",
	} {
		if hasID(got, id) != nil {
			t.Errorf("unexpected %s", id)
		}
	}
	if f := hasID(got, "php:upload-progress:system:www"); f != nil && len(f.References) < 2 {
		t.Errorf("upload-progress finding should cite both CVEs: %v", f.References)
	}
}

func TestPHPRuleSupportedBranchAndNoPHP(t *testing.T) {
	fx := newFixture(t)
	if got := runRule(NewPHPRule(), nil, fx.opts()); len(got) != 0 {
		t.Fatalf("no PHP installed: got %v", ids(got))
	}
	fx.file("/etc/php.ini", "session.upload_progress.enabled = 0\n")
	got := runRule(NewPHPRule(), phpFacts("8.3.12", "1.el9"), fx.opts())
	if hasPrefix(got, "php:eol-branch") != 0 || hasPrefix(got, "php:upload-progress") != 0 {
		t.Errorf("8.3 with upload progress off: got %v", ids(got))
	}
}

func TestParseINIAndPools(t *testing.T) {
	set := map[string]string{}
	parseINI("[Session]\n; comment\nsession.save_path = \"3;/var/lib/php/session\"\nkey=value ; trailing\n", set)
	if set["session.save_path"] != "3;/var/lib/php/session" || set["key"] != "value" {
		t.Errorf("parseINI = %v", set)
	}
	pools := parsePools("system", "/etc/php-fpm.d/x.conf", "[a]\nuser = apache\n[b]\nuser = nginx\nphp_flag[display_errors] = off\n")
	if len(pools) != 2 || pools[1].User != "nginx" || pools[1].Settings["display_errors"] != "off" {
		t.Errorf("parsePools = %+v", pools)
	}
}
