package rules

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/finding"
)

// WebServerRule audits installed web server configs. Skips silently when no
// web server is present (no config files found in standard locations).
// Currently covers nginx and Apache httpd; Caddy / lighttpd configs are
// future work.
type WebServerRule struct{}

func NewWebServerRule() *WebServerRule { return &WebServerRule{} }

func (r *WebServerRule) Name() string { return "web-server" }

func (r *WebServerRule) Run(ctx context.Context, facts *collector.Facts, log *slog.Logger, opts Options) []finding.Finding {
	var findings []finding.Finding
	findings = append(findings, r.scanNginx(opts)...)
	findings = append(findings, r.scanApache(opts)...)
	log.Debug("web-server rule scanned", "level", opts.Level.String(), "findings", len(findings))
	return findings
}

// --- nginx ------------------------------------------------------------------

func (r *WebServerRule) scanNginx(opts Options) []finding.Finding {
	const conf = "/etc/nginx/nginx.conf"
	directives, err := readNginxDirectives(conf)
	if err != nil {
		return nil
	}
	var out []finding.Finding
	now := time.Now()
	mk := func(minLevel Level, id, title, evidence string, sev finding.Severity, fix string) {
		if minLevel > opts.Level {
			return
		}
		out = append(out, finding.Finding{
			ID:          "nginx:" + id,
			Category:    finding.CategoryConfig,
			Severity:    sev,
			Title:       title,
			Evidence:    evidence,
			Remediation: fix,
			DetectedAt:  now,
			Source:      "lync-rules",
		})
	}

	if directives["server_tokens"] != "off" {
		mk(LevelBasic, "server-tokens",
			"nginx leaks version (server_tokens not 'off')",
			"server_tokens "+orNone(directives["server_tokens"]),
			finding.SeverityLow,
			"add `server_tokens off;` inside http {} block; reload nginx")
	}
	if protos := directives["ssl_protocols"]; protos != "" {
		for _, p := range strings.Fields(protos) {
			if p == "SSLv2" || p == "SSLv3" || p == "TLSv1" || p == "TLSv1.1" {
				mk(LevelBasic, "weak-ssl-proto",
					"nginx allows deprecated TLS protocol: "+p,
					"ssl_protocols "+protos,
					finding.SeverityHigh,
					"set `ssl_protocols TLSv1.2 TLSv1.3;` in nginx.conf; reload nginx")
				break
			}
		}
	}
	if _, hasHSTS := directives["add_header_strict-transport-security"]; !hasHSTS {
		mk(LevelMedium, "no-hsts",
			"nginx serves HTTPS without HSTS header",
			"no add_header Strict-Transport-Security found",
			finding.SeverityMedium,
			"add `add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;` to server {} blocks serving HTTPS")
	}
	if _, hasXFO := directives["add_header_x-frame-options"]; !hasXFO {
		mk(LevelMedium, "no-xfo",
			"nginx missing X-Frame-Options header (clickjacking exposure)",
			"no add_header X-Frame-Options found",
			finding.SeverityLow,
			"add `add_header X-Frame-Options SAMEORIGIN always;` to server {} block")
	}
	if _, hasNoSniff := directives["add_header_x-content-type-options"]; !hasNoSniff {
		mk(LevelMedium, "no-content-type-options",
			"nginx missing X-Content-Type-Options header",
			"no add_header X-Content-Type-Options found",
			finding.SeverityLow,
			"add `add_header X-Content-Type-Options nosniff always;` to server {} block")
	}
	if v := directives["ssl_ciphers"]; v != "" {
		lower := strings.ToLower(v)
		for _, weak := range []string{"rc4", "md5", "null", "export", "des"} {
			if strings.Contains(lower, weak) {
				mk(LevelStrict, "weak-cipher-"+weak,
					"nginx allows weak SSL cipher family: "+weak,
					"ssl_ciphers "+v,
					finding.SeverityMedium,
					"tighten ssl_ciphers to a Mozilla 'intermediate' or 'modern' recommendation")
				break
			}
		}
	}
	if v := directives["autoindex"]; v == "on" {
		mk(LevelMedium, "autoindex",
			"nginx directory autoindex enabled",
			"autoindex on",
			finding.SeverityLow,
			"set `autoindex off;` (default) unless directory listings are intentional")
	}
	return out
}

func readNginxDirectives(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSuffix(line, ";")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "add_header" && len(fields) >= 2 {
			// add_header X-Foo "value"  -->  add_header_x-foo = "value"
			subkey := "add_header_" + strings.ToLower(fields[1])
			out[subkey] = strings.Join(fields[2:], " ")
			continue
		}
		out[key] = strings.Join(fields[1:], " ")
	}
	return out, s.Err()
}

// --- Apache httpd -----------------------------------------------------------

func (r *WebServerRule) scanApache(opts Options) []finding.Finding {
	// httpd lives under /etc/httpd/ on RHEL family, /etc/apache2/ on Debian
	// family. Walk both with a small set of candidate roots to also catch
	// modules.d / conf.d additions.
	roots := []string{
		"/etc/httpd/conf/httpd.conf",
		"/etc/httpd/conf.d",
		"/etc/apache2/apache2.conf",
		"/etc/apache2/conf-enabled",
		"/etc/apache2/sites-enabled",
	}
	directives, found := readApacheDirectives(roots)
	if !found {
		return nil
	}
	var out []finding.Finding
	now := time.Now()
	mk := func(minLevel Level, id, title, evidence string, sev finding.Severity, fix string) {
		if minLevel > opts.Level {
			return
		}
		out = append(out, finding.Finding{
			ID:          "apache:" + id,
			Category:    finding.CategoryConfig,
			Severity:    sev,
			Title:       title,
			Evidence:    evidence,
			Remediation: fix,
			DetectedAt:  now,
			Source:      "lync-rules",
		})
	}

	if v := strings.ToLower(directives["servertokens"]); v != "prod" && v != "productonly" {
		mk(LevelBasic, "server-tokens",
			"Apache leaks version (ServerTokens not 'Prod')",
			"ServerTokens "+orNone(directives["servertokens"]),
			finding.SeverityLow,
			"set `ServerTokens Prod` in httpd.conf")
	}
	if v := strings.ToLower(directives["serversignature"]); v != "off" {
		mk(LevelBasic, "server-signature",
			"Apache adds server signature to error pages",
			"ServerSignature "+orNone(directives["serversignature"]),
			finding.SeverityLow,
			"set `ServerSignature Off`")
	}
	if v := strings.ToLower(directives["traceenable"]); v != "off" {
		mk(LevelBasic, "trace-enabled",
			"Apache HTTP TRACE method enabled (XST risk)",
			"TraceEnable "+orNone(directives["traceenable"]),
			finding.SeverityMedium,
			"set `TraceEnable Off` in httpd.conf")
	}
	if v := directives["options"]; v != "" {
		opts := strings.ToLower(v)
		if strings.Contains(opts, "indexes") && !strings.Contains(opts, "-indexes") {
			mk(LevelMedium, "indexes",
				"Apache Options Indexes enabled (directory listings exposed)",
				"Options "+v,
				finding.SeverityLow,
				"remove Indexes from Options, e.g. `Options FollowSymLinks` (no Indexes)")
		}
	}
	if v := directives["ssl_protocol"]; v != "" {
		for _, p := range strings.Fields(v) {
			if p == "+SSLv3" || p == "+TLSv1" || p == "+TLSv1.1" || p == "SSLv3" || p == "TLSv1" || p == "TLSv1.1" {
				mk(LevelBasic, "weak-ssl-proto",
					"Apache allows deprecated TLS/SSL protocol: "+strings.TrimPrefix(p, "+"),
					"SSLProtocol "+v,
					finding.SeverityHigh,
					"set `SSLProtocol -all +TLSv1.2 +TLSv1.3`")
				break
			}
		}
	}
	return out
}

func readApacheDirectives(roots []string) (map[string]string, bool) {
	out := map[string]string{}
	found := false
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		found = true
		if !info.IsDir() {
			mergeApacheDirectives(root, out)
			continue
		}
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(p, ".conf") {
				return nil
			}
			mergeApacheDirectives(p, out)
			return nil
		})
	}
	return out, found
}

func mergeApacheDirectives(path string, out map[string]string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "<") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		// Last-wins for Apache directives at the global scope.
		out[key] = strings.Join(fields[1:], " ")
	}
}
