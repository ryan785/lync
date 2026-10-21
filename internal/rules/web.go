package rules

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

func init() {
	register(
		CheckInfo{ID: "web:sensitive-file", Rule: "web-exposure", Severity: finding.SeverityHigh,
			Description: "Secrets, VCS metadata, dumps, backups, keys or AI-agent notes (CLAUDE.md/AGENTS.md) under an nginx/httpd document root"},
		CheckInfo{ID: "web:phpinfo", Rule: "web-exposure", Severity: finding.SeverityMedium,
			Description: "phpinfo() page under a document root"},
		CheckInfo{ID: "web:shell-stub", Rule: "web-exposure", Severity: finding.SeverityHigh,
			Description: "PHP code calling shell_exec/system/passthru/proc_open in a file without a .php extension under a document root"},
		CheckInfo{ID: "web:php-writable-dir", Rule: "web-exposure", Severity: finding.SeverityHigh,
			Description: "Directory writable by the web/PHP user inside a server whose PHP location would execute uploaded .php files"},
		CheckInfo{ID: "web:fastcgi-dead", Rule: "web-exposure", Severity: finding.SeverityHigh,
			Description: "nginx fastcgi_pass points at a missing socket or a port nothing listens on"},
		CheckInfo{ID: "web:php-no-try-files", Rule: "web-exposure", Severity: finding.SeverityMedium,
			Description: "PHP location without try_files $uri =404 (path-info / arbitrary file execution with cgi.fix_pathinfo)"},
		CheckInfo{ID: "web:error-page-php", Rule: "web-exposure", Severity: finding.SeverityLow,
			Description: "error_page routed to a .php script"},
		CheckInfo{ID: "web:origin-exposed", Rule: "web-exposure", Severity: finding.SeverityMedium,
			Description: "vhost is set up for Cloudflare but the origin accepts direct connections from anywhere"},
		CheckInfo{ID: "tls:cert-expiry", Rule: "web-exposure", Severity: finding.SeverityHigh,
			Description: "TLS certificate referenced by nginx is expired or expires within 14 days"},
	)
}

// WebExposureRule covers document-root contents and nginx routing.
type WebExposureRule struct{}

func NewWebExposureRule() *WebExposureRule { return &WebExposureRule{} }

func (r *WebExposureRule) Name() string { return "web-exposure" }

const (
	webWalkDepth   = 8
	webWalkEntries = 60000
)

func (r *WebExposureRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	h := opts.host()
	var out []finding.Finding
	var model *nginxModel
	if c := h.loadNginx(ctx); c != nil {
		model = nginxModelOf(c)
	}
	roots := h.webRoots(ctx)
	if opts.on("web:sensitive-file") || opts.on("web:phpinfo") || opts.on("web:shell-stub") {
		dotDenied := model != nil && deniesDotfiles(model)
		for _, root := range roots {
			out = append(out, scanWebRoot(h, root, dotDenied, opts)...)
		}
	}
	if model == nil {
		return out
	}
	if opts.on("web:php-writable-dir") {
		out = append(out, phpWritableDirs(h, model, facts)...)
	}
	if opts.on("web:fastcgi-dead") {
		out = append(out, fastcgiDead(ctx, h, model)...)
	}
	for _, s := range model.Servers {
		for _, l := range s.Locations {
			if opts.on("web:php-no-try-files") && l.FastCGI != "" && !l.DenyAll && !hasTryFiles404(l.TryFiles) {
				out = append(out, mkFinding(h, "web:php-no-try-files", s.Label()+":"+l.Match, finding.CategoryConfig, finding.SeverityMedium,
					fmt.Sprintf("nginx PHP location without try_files $uri =404 (%s, location %s)", s.Label(), l.Match),
					fmt.Sprintf("%s: location %s { fastcgi_pass %s; } has no `try_files $uri =404;`", s.File, l.Match, l.FastCGI),
					"Add `try_files $uri =404;` inside the PHP location (and keep cgi.fix_pathinfo=0), then `nginx -t && systemctl reload nginx`",
					"https://www.nginx.com/resources/wiki/start/topics/examples/phpfcgi/"))
			}
		}
		if opts.on("web:error-page-php") {
			for _, ep := range s.ErrorPages {
				if len(ep) > 0 && strings.Contains(ep[len(ep)-1], ".php") {
					out = append(out, mkFinding(h, "web:error-page-php", s.Label()+":"+ep[len(ep)-1], finding.CategoryConfig, finding.SeverityLow,
						"nginx error_page handled by a PHP script ("+s.Label()+")",
						s.File+": error_page "+strings.Join(ep, " "),
						"Serve static error pages (error_page 404 /404.html;) so error paths don't reach PHP, then reload nginx"))
				}
			}
		}
	}
	if opts.on("web:origin-exposed") {
		out = append(out, originExposed(ctx, h, model)...)
	}
	if opts.on("tls:cert-expiry") {
		out = append(out, certExpiry(h, model)...)
	}
	return out
}

func hasTryFiles404(args []string) bool {
	return len(args) >= 2 && args[len(args)-1] == "=404"
}

// deniesDotfiles reports whether some location blocks /. paths.
func deniesDotfiles(m *nginxModel) bool {
	for _, s := range m.Servers {
		for _, l := range s.Locations {
			if l.DenyAll && strings.Contains(l.Match, `/\.`) {
				return true
			}
		}
	}
	return false
}

type sensitiveKind struct {
	sev   finding.Severity
	label string
	dot   bool // dotfile: nginx `location ~ /\.` deny rules cover it
}

// classifySensitive decides whether a name under a webroot is sensitive.
func classifySensitive(name string, isDir bool) (sensitiveKind, bool) {
	lower := strings.ToLower(name)
	if isDir {
		switch lower {
		case ".git", ".svn", ".hg":
			return sensitiveKind{finding.SeverityHigh, "version-control metadata (source + history downloadable)", true}, true
		case "backup", "backups", ".backup":
			return sensitiveKind{finding.SeverityMedium, "backup directory", strings.HasPrefix(lower, ".")}, true
		}
		return sensitiveKind{}, false
	}
	switch {
	case lower == "claude.md" || lower == "agents.md" || lower == "gemini.md" || lower == ".cursorrules":
		return sensitiveKind{finding.SeverityMedium, "AI agent notes (often describe infrastructure, paths, credentials)", lower == ".cursorrules"}, true
	case lower == ".env" || strings.HasPrefix(lower, ".env."):
		return sensitiveKind{finding.SeverityHigh, "environment file (credentials)", true}, true
	case lower == ".htpasswd" || lower == ".git-credentials" || lower == ".npmrc" || lower == ".pgpass":
		return sensitiveKind{finding.SeverityHigh, "credential file", true}, true
	case strings.HasPrefix(lower, "id_rsa") || strings.HasPrefix(lower, "id_ecdsa") || strings.HasPrefix(lower, "id_ed25519") || strings.HasPrefix(lower, "id_dsa"):
		return sensitiveKind{finding.SeverityCritical, "SSH private key", false}, true
	case strings.HasSuffix(lower, ".key") || strings.HasSuffix(lower, ".p12") || strings.HasSuffix(lower, ".pfx"):
		return sensitiveKind{finding.SeverityHigh, "private key / keystore", false}, true
	case strings.HasSuffix(lower, ".sql") || strings.HasSuffix(lower, ".sql.gz") || strings.HasSuffix(lower, ".sql.zip") || strings.HasSuffix(lower, ".dump"):
		return sensitiveKind{finding.SeverityHigh, "database dump", false}, true
	case strings.HasSuffix(lower, ".bak") || strings.HasSuffix(lower, ".old") || strings.HasSuffix(lower, ".orig") ||
		strings.HasSuffix(lower, ".swp") || strings.HasSuffix(lower, "~") || strings.HasSuffix(lower, ".save"):
		return sensitiveKind{finding.SeverityMedium, "backup/editor copy (served as plain text, exposes source)", strings.HasPrefix(lower, ".")}, true
	case (strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".zip") ||
		strings.HasSuffix(lower, ".tar") || strings.HasSuffix(lower, ".7z") || strings.HasSuffix(lower, ".rar")) &&
		(strings.Contains(lower, "backup") || strings.Contains(lower, "bak") || strings.Contains(lower, "site") ||
			strings.Contains(lower, "www") || strings.Contains(lower, "html") || strings.Contains(lower, "db")):
		return sensitiveKind{finding.SeverityHigh, "site/database archive", false}, true
	}
	return sensitiveKind{}, false
}

var shellFuncs = []string{"shell_exec(", "system(", "passthru(", "proc_open(", "popen(", "pcntl_exec("}

func scanWebRoot(h *Host, root string, dotDenied bool, opts Options) []finding.Finding {
	var out []finding.Finding
	h.Walk(root, webWalkDepth, webWalkEntries, func(p string, d fs.DirEntry) error {
		name := d.Name()
		if p != root && opts.on("web:sensitive-file") {
			if k, ok := classifySensitive(name, d.IsDir()); ok {
				sev := k.sev
				note := ""
				if k.dot && dotDenied {
					sev = finding.SeverityLow
					note = " (an nginx `location ~ /\\.` deny rule appears to block dotfiles; verify with curl)"
				}
				out = append(out, mkFinding(h, "web:sensitive-file", p, finding.CategoryFilesystem, sev,
					"Sensitive file under web root: "+p,
					k.label+" inside document root "+root+note,
					fmt.Sprintf("Move it out of the document root (mv %s /root/) or deny it in nginx; verify with: curl -sI https://<site>/%s", p, strings.TrimPrefix(strings.TrimPrefix(p, root), "/")),
					"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"))
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() {
			if name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		ext := strings.ToLower(path.Ext(name))
		isPHP := ext == ".php"
		textual := isPHP || ext == "" || ext == ".txt" || ext == ".inc" || ext == ".phtml" || ext == ".html" ||
			ext == ".htm" || ext == ".jpg" || ext == ".png" || ext == ".gif" || ext == ".ico" || ext == ".log" || ext == ".php5" || ext == ".pht"
		if !textual {
			return nil
		}
		b, err := h.ReadFileLimit(p, 256*1024)
		if err != nil {
			return nil
		}
		body := string(b)
		if isPHP && opts.on("web:phpinfo") && len(b) < 64*1024 && strings.Contains(body, "phpinfo(") {
			out = append(out, mkFinding(h, "web:phpinfo", p, finding.CategoryConfig, finding.SeverityMedium,
				"phpinfo() page under web root: "+p,
				"file calls phpinfo(): discloses PHP version, modules, paths and environment variables",
				"rm "+p+"  (or move it outside the document root)"))
		}
		if !isPHP && opts.on("web:shell-stub") && (strings.Contains(body, "<?php") || strings.Contains(body, "<?=")) {
			for _, fn := range shellFuncs {
				if strings.Contains(body, fn) {
					out = append(out, mkFinding(h, "web:shell-stub", p, finding.CategoryRuntime, finding.SeverityHigh,
						"Possible web shell under web root: "+p,
						fmt.Sprintf("non-.php file contains PHP code calling %s", strings.TrimSuffix(fn, "(")),
						"Inspect it now (head -c 2000 "+p+"); if unexpected, preserve a copy for forensics, remove it, and review access logs for requests to it"))
					break
				}
			}
		}
		return nil
	})
	return out
}

// webUsers returns accounts that nginx/httpd/php-fpm run as.
func webUsers(h *Host) []Account {
	names := map[string]bool{"nginx": true, "apache": true, "www-data": true, "httpd": true}
	for _, p := range phpPools(h) {
		if p.User != "" {
			names[p.User] = true
		}
	}
	var out []Account
	for n := range names {
		if a, ok := h.Account(n); ok && a.UID != 0 {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func phpWritableDirs(h *Host, m *nginxModel, facts *collector.Facts) []finding.Finding {
	users := webUsers(h)
	if len(users) == 0 {
		return nil
	}
	var out []finding.Finding
	seen := map[string]bool{}
	for _, s := range m.Servers {
		phpLoc := ""
		for _, l := range s.Locations {
			if l.FastCGI != "" && !l.DenyAll {
				phpLoc = l.Match
				break
			}
		}
		if phpLoc == "" || s.Root == "" || seen[s.Root] {
			continue
		}
		seen[s.Root] = true
		h.Walk(s.Root, 6, 20000, func(p string, d fs.DirEntry) error {
			if !d.IsDir() {
				return nil
			}
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			for _, u := range users {
				if h.WritableBy(p, u) {
					if blockedByLocation(s, strings.TrimPrefix(p, s.Root)) {
						return filepath.SkipDir
					}
					out = append(out, mkFinding(h, "web:php-writable-dir", p, finding.CategoryConfig, finding.SeverityHigh,
						fmt.Sprintf("Directory writable by %s is served by a PHP-executing vhost: %s", u.Name, p),
						fmt.Sprintf("%s (server %s, %s) passes `location %s` to PHP; %s can write into %s, so an uploaded .php file there would execute",
							s.File, s.Label(), s.Root, phpLoc, u.Name, p),
						fmt.Sprintf("Deny script execution under it in nginx: `location ^~ %s/ { location ~ \\.php$ { deny all; } }` (or chown root and chmod 755 if writes aren't needed)", strings.TrimPrefix(p, s.Root)),
						"https://cwe.mitre.org/data/definitions/434.html"))
					return filepath.SkipDir // report top-most writable dir only
				}
			}
			return nil
		})
	}
	return out
}

// blockedByLocation reports whether a location with deny all / return 403
// covers this URI prefix.
func blockedByLocation(s nginxServer, uri string) bool {
	if uri == "" {
		return false
	}
	for _, l := range s.Locations {
		if !l.DenyAll {
			continue
		}
		f := strings.Fields(l.Match)
		if len(f) == 0 {
			continue
		}
		prefix := f[len(f)-1]
		if strings.HasPrefix(uri+"/", strings.TrimSuffix(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

func fastcgiDead(ctx context.Context, h *Host, m *nginxModel) []finding.Finding {
	ls, lsOK := h.Listeners(ctx)
	var out []finding.Finding
	seen := map[string]bool{}
	for _, s := range m.Servers {
		for _, l := range s.Locations {
			if l.FastCGI == "" || strings.Contains(l.FastCGI, "$") {
				continue
			}
			targets := []string{l.FastCGI}
			if ups, ok := m.Upstreams[l.FastCGI]; ok {
				targets = ups
			}
			for _, t := range targets {
				if seen[t] {
					continue
				}
				seen[t] = true
				problem := ""
				switch {
				case strings.HasPrefix(t, "unix:"):
					sock := strings.TrimPrefix(t, "unix:")
					if !h.Exists(sock) {
						problem = "socket " + sock + " does not exist (php-fpm pool stopped, renamed, or a different PHP version's socket)"
					}
				case lsOK:
					_, portStr, ok := splitHostPort(t)
					if !ok {
						continue
					}
					port, err := strconv.Atoi(portStr)
					if err == nil && !listeningOn(ls, "tcp", port) {
						problem = "nothing listens on TCP port " + portStr
					}
				}
				if problem != "" {
					out = append(out, mkFinding(h, "web:fastcgi-dead", t, finding.CategoryConfig, finding.SeverityHigh,
						"nginx fastcgi_pass target is dead: "+t,
						fmt.Sprintf("%s: server %s location %s -> fastcgi_pass %s; %s", s.File, s.Label(), l.Match, t, problem),
						"Point fastcgi_pass at the running pool's `listen` (grep -r '^listen' /etc/php-fpm.d /etc/opt/remi/*/php-fpm.d) or start the pool; then nginx -t && systemctl reload nginx. A dead upstream can also mean nginx now serves .php files as plain text if the location falls through."))
				}
			}
		}
	}
	return out
}

// cloudflareRanges are Cloudflare's published edge prefixes (subset is
// enough to recognise intent; full list at cloudflare.com/ips).
var cloudflareRanges = []string{"173.245.48.", "103.21.244.", "103.22.200.", "103.31.4.", "141.101.", "108.162.",
	"190.93.", "188.114.", "197.234.240.", "198.41.", "162.158.", "104.16.", "104.24.", "172.64.", "131.0.72.", "2400:cb00:", "2606:4700:", "2803:f800:", "2405:b500:", "2405:8100:", "2a06:98c0:", "2c0f:f248:"}

func isCloudflareRange(s string) bool {
	for _, p := range cloudflareRanges {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func originExposed(ctx context.Context, h *Host, m *nginxModel) []finding.Finding {
	ls, ok := h.Listeners(ctx)
	if !ok {
		return nil
	}
	public := false
	for _, l := range ls {
		if l.Proto == "tcp" && (l.Port == 80 || l.Port == 443) && !l.Loopback() {
			public = true
		}
	}
	if !public {
		return nil
	}
	globalMarker := false
	for _, c := range m.Comments {
		if strings.Contains(strings.ToLower(c), "cloudflare") {
			globalMarker = true
		}
	}
	var out []finding.Finding
	for _, s := range m.Servers {
		marker := ""
		for _, v := range s.RealIP {
			if strings.EqualFold(v, "CF-Connecting-IP") || isCloudflareRange(v) {
				marker = "set_real_ip_from/real_ip_header for Cloudflare"
				break
			}
		}
		if marker == "" && globalMarker && len(s.RealIP) > 0 {
			marker = "real_ip config plus 'cloudflare' comments"
		}
		if marker == "" {
			continue
		}
		restricted := false
		if s.DenyAll {
			for _, a := range s.Allows {
				if isCloudflareRange(a) {
					restricted = true
				}
			}
		}
		if restricted {
			continue
		}
		out = append(out, mkFinding(h, "web:origin-exposed", s.Label(), finding.CategoryNetwork, finding.SeverityMedium,
			"Cloudflare-fronted vhost is reachable directly at the origin: "+s.Label(),
			fmt.Sprintf("%s: %s, but no `allow <cloudflare ranges>; deny all;` and ports 80/443 listen on a public address. Attackers can bypass Cloudflare's WAF/rate limits by hitting the origin IP.", s.File, marker),
			"Restrict 80/443 to Cloudflare ranges (firewalld ipset from https://www.cloudflare.com/ips-v4 + ips-v6, or nginx allow/deny), or use Cloudflare Tunnel / Authenticated Origin Pulls",
			"https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/"))
	}
	return out
}

func certExpiry(h *Host, m *nginxModel) []finding.Finding {
	var out []finding.Finding
	seen := map[string]bool{}
	now := h.now()
	for _, s := range m.Servers {
		for _, c := range s.Certs {
			if c == "" || strings.Contains(c, "$") || seen[c] {
				continue
			}
			seen[c] = true
			b, err := h.ReadFile(c)
			if err != nil {
				continue
			}
			blk, _ := pem.Decode(b)
			if blk == nil {
				continue
			}
			cert, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				continue
			}
			left := cert.NotAfter.Sub(now)
			ev := fmt.Sprintf("%s (server %s): subject %q, notAfter %s", c, s.Label(), cert.Subject.CommonName, cert.NotAfter.UTC().Format(time.RFC3339))
			fix := "Renew (certbot renew --cert-name <name> / acme.sh --renew) and reload nginx; check the renewal timer: systemctl list-timers | grep -E 'certbot|acme'"
			switch {
			case left <= 0:
				out = append(out, mkFinding(h, "tls:cert-expiry", c, finding.CategoryTLS, finding.SeverityHigh,
					fmt.Sprintf("TLS certificate expired %d days ago: %s", ageDays(-left), c), ev, fix))
			case left < 14*24*time.Hour:
				out = append(out, mkFinding(h, "tls:cert-expiry", c, finding.CategoryTLS, finding.SeverityMedium,
					fmt.Sprintf("TLS certificate expires in %d days: %s", ageDays(left), c), ev, fix))
			}
		}
	}
	return out
}
