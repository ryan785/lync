package rules

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/fs"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ryan785/lync/internal/finding"
)

const nginxMain = `
user nginx;
events {}
http {
    # behind cloudflare
    include /etc/nginx/conf.d/*.conf;
}
`

const nginxSite = `
upstream phpfpm { server 127.0.0.1:9000; }
server {
    listen 443 ssl;
    server_name shop.example.com;
    root /var/www/shop;
    ssl_certificate /etc/pki/tls/certs/shop.crt;
    set_real_ip_from 173.245.48.0/20;
    real_ip_header CF-Connecting-IP;
    error_page 404 /404.php;
    location ~ /\. { deny all; }
    location ~ \.php$ {
        fastcgi_pass unix:/run/php-fpm/www.sock;
        include fastcgi_params;
    }
    location /api/ {
        fastcgi_pass phpfpm;
        try_files $uri =404;
    }
}
server {
    listen 80;
    server_name blog.example.com;
    root /var/www/blog;
    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_pass 127.0.0.1:9001;
    }
}
`

func certPEM(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "shop.example.com"},
		NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func webFixture(t *testing.T) *fixtureHost {
	fx := newFixture(t)
	fx.file("/etc/passwd", passwdFixture).file("/etc/group", groupFixture).
		file("/etc/nginx/nginx.conf", nginxMain).
		file("/etc/nginx/conf.d/shop.conf", nginxSite).
		file("/var/www/shop/index.php", "<?php echo 'hi';").
		file("/var/www/shop/.env", "DB_PASSWORD=x").
		file("/var/www/shop/CLAUDE.md", "# notes").
		file("/var/www/shop/.git/HEAD", "ref: refs/heads/main").
		file("/var/www/shop/backup/site.sql", "CREATE TABLE").
		file("/var/www/shop/info.php", "<?php phpinfo(); ?>").
		file("/var/www/shop/uploads/avatar.jpg", "GIF89a <?php echo 'build'; $d = shell_exec('date'); ?>").
		file("/var/www/shop/uploads/ok.jpg", "\xff\xd8 binary").
		file("/var/www/blog/index.php", "<?php").
		file("/var/www/blog/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----").
		file("/etc/pki/tls/certs/shop.crt", certPEM(t, fixedNow.Add(5*24*time.Hour))).
		// uploads is owned by nginx and writable
		meta("/var/www/shop/uploads", fs.ModeDir|0o755, 991, 991).
		cmd("ss -H -tulnp", "tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=1,fd=6))\ntcp LISTEN 0 511 127.0.0.1:9000 0.0.0.0:* users:((\"php-fpm\",pid=2,fd=6))\n")
	return fx
}

func TestWebExposureRule(t *testing.T) {
	fx := webFixture(t)
	got := runRule(NewWebExposureRule(), nil, fx.opts())
	requireShape(t, got)

	cases := []struct {
		id  string
		sev finding.Severity
	}{
		{"web:sensitive-file:/var/www/shop/.env", finding.SeverityLow}, // dotfiles denied by location ~ /\.
		{"web:sensitive-file:/var/www/shop/.git", finding.SeverityLow},
		{"web:sensitive-file:/var/www/shop/CLAUDE.md", finding.SeverityMedium},
		{"web:sensitive-file:/var/www/shop/backup", finding.SeverityMedium},
		{"web:sensitive-file:/var/www/blog/id_rsa", finding.SeverityCritical},
		{"web:phpinfo:/var/www/shop/info.php", finding.SeverityMedium},
		{"web:shell-stub:/var/www/shop/uploads/avatar.jpg", finding.SeverityHigh},
		{"web:php-writable-dir:/var/www/shop/uploads", finding.SeverityHigh},
		{"web:fastcgi-dead:unix:/run/php-fpm/www.sock", finding.SeverityHigh},
		{"web:fastcgi-dead:127.0.0.1:9001", finding.SeverityHigh},
		{`web:php-no-try-files:shop.example.com:~ \.php$`, finding.SeverityMedium},
		{"web:error-page-php:shop.example.com:/404.php", finding.SeverityLow},
		{"web:origin-exposed:shop.example.com", finding.SeverityMedium},
		{"tls:cert-expiry:/etc/pki/tls/certs/shop.crt", finding.SeverityMedium},
	}
	for _, c := range cases {
		f := hasID(got, c.id)
		if f == nil {
			t.Errorf("missing %s\n got: %v", c.id, ids(got))
			continue
		}
		if f.Severity != c.sev {
			t.Errorf("%s severity = %s, want %s", c.id, f.Severity, c.sev)
		}
	}
	// Negative cases.
	for _, id := range []string{
		"web:fastcgi-dead:127.0.0.1:9000",       // listening
		"web:php-no-try-files:blog.example.com", // has try_files
		"web:shell-stub:/var/www/shop/uploads/ok.jpg",
		"web:origin-exposed:blog.example.com", // no CF markers
		"web:php-writable-dir:/var/www/blog",
	} {
		for _, f := range got {
			if strings.HasPrefix(f.ID, id) {
				t.Errorf("unexpected finding %s", f.ID)
			}
		}
	}
}

func TestWebExposureToggles(t *testing.T) {
	fx := webFixture(t)
	o := fx.opts()
	o.Toggles = Toggles{Disable: []string{"web:sensitive-file", "tls"}}
	got := runRule(NewWebExposureRule(), nil, o)
	if n := hasPrefix(got, "web:sensitive-file"); n != 0 {
		t.Errorf("disabled check still produced %d findings", n)
	}
	if n := hasPrefix(got, "tls:"); n != 0 {
		t.Errorf("disabled prefix still produced %d findings", n)
	}
	if hasPrefix(got, "web:phpinfo") == 0 {
		t.Error("other checks must still run")
	}
}

func TestWebNoNginxNoPanic(t *testing.T) {
	fx := newFixture(t) // empty root, no tools
	if got := runRule(NewWebExposureRule(), nil, fx.opts()); len(got) != 0 {
		t.Errorf("empty host: got %v", ids(got))
	}
}

func TestNginxDumpFallback(t *testing.T) {
	fx := newFixture(t)
	fx.cmd("nginx -T", "nginx: the configuration file /usr/local/nginx/conf/nginx.conf syntax is ok\n"+
		"# configuration file /usr/local/nginx/conf/nginx.conf:\nhttp { include sites/*.conf; }\n"+
		"# configuration file /usr/local/nginx/conf/sites/a.conf:\nserver { server_name a.test; root /srv/a; location ~ \\.php$ { fastcgi_pass unix:/run/a.sock; } }\n")
	c := fx.h.loadNginx(context.Background())
	if c == nil {
		t.Fatal("nginx -T fallback returned nil")
	}
	m := nginxModelOf(c)
	if len(m.Servers) != 1 || m.Servers[0].Root != "/srv/a" || m.Servers[0].Locations[0].FastCGI != "unix:/run/a.sock" {
		t.Errorf("model = %+v", m.Servers)
	}
}

func TestCertExpired(t *testing.T) {
	fx := webFixture(t)
	fx.file("/etc/pki/tls/certs/shop.crt", certPEM(t, fixedNow.Add(-3*24*time.Hour)))
	got := runRule(NewWebExposureRule(), nil, fx.opts())
	if f := hasID(got, "tls:cert-expiry:/etc/pki/tls/certs/shop.crt"); f == nil || f.Severity != finding.SeverityHigh {
		t.Errorf("expired cert: %+v", f)
	}
}

func TestClassifySensitive(t *testing.T) {
	cases := []struct {
		name string
		dir  bool
		want bool
	}{
		{".env.production", false, true}, {"AGENTS.md", false, true}, {"dump.sql.gz", false, true},
		{"index.php.bak", false, true}, {"www-backup.tar.gz", false, true}, {".git", true, true},
		{"index.php", false, false}, {"logo.png", false, false}, {"assets", true, false}, {"bundle.zip", false, false},
	}
	for _, c := range cases {
		if _, got := classifySensitive(c.name, c.dir); got != c.want {
			t.Errorf("classifySensitive(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
