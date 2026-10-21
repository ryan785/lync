package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryan785/lync/internal/collector"
	"github.com/ryan785/lync/internal/config"
	"github.com/ryan785/lync/internal/feed"
	"github.com/ryan785/lync/internal/finding"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func facts() *collector.Facts {
	return &collector.Facts{Hostname: "web1", OS: collector.OSInfo{PrettyName: "Debian GNU/Linux 12"},
		Packages: []collector.Package{{Name: "libssl3:amd64", Manager: "dpkg"}}}
}

func cveF(id, pkg string, sev finding.Severity, fixed string) finding.Finding {
	return finding.Finding{ID: id + ":" + pkg, Category: finding.CategoryCVE, CVE: id, Package: pkg, Severity: sev,
		FixedIn: fixed, Installed: pkg + "-1", Title: id + " affects " + pkg, Remediation: "update " + pkg}
}

// recorder is a fake channel.
type recorder struct {
	name string
	msgs []*Message
	fail bool
}

func (r *recorder) Name() string { return r.name }
func (r *recorder) Send(_ context.Context, m *Message) error {
	if r.fail {
		return errors.New("down")
	}
	r.msgs = append(r.msgs, m)
	return nil
}

func newTestNotifier(t *testing.T, chans ...Channel) *Notifier {
	return &Notifier{cfg: config.NotifyConfig{Enabled: true, MinSeverity: "high", StateFile: filepath.Join(t.TempDir(), "state.json")},
		log: quiet, channels: chans, now: time.Now}
}

func TestProcessDiffsAndDedupes(t *testing.T) {
	a, b := &recorder{name: "a"}, &recorder{name: "b", fail: true}
	n := newTestNotifier(t, a, b)
	ctx := context.Background()
	complete := &feed.ScanSources{Complete: true}
	scan1 := []finding.Finding{cveF("CVE-1", "openssl", finding.SeverityCritical, "2"), cveF("CVE-2", "curl", finding.SeverityLow, "3")}

	n.process(ctx, facts(), scan1, complete, "", "")
	if len(a.msgs) != 1 || a.msgs[0].Event != "baseline" || len(a.msgs[0].Current) != 1 {
		t.Fatalf("baseline: %+v", a.msgs)
	}
	// Same findings again: nothing new to say.
	n.process(ctx, facts(), scan1, complete, "", "")
	if len(a.msgs) != 1 {
		t.Fatalf("re-sent unchanged findings: %d messages", len(a.msgs))
	}
	// New High finding, a fix appears for an unfixed one.
	scan2 := []finding.Finding{cveF("CVE-1", "openssl", finding.SeverityCritical, "2"), cveF("CVE-3", "bash", finding.SeverityHigh, ""), cveF("CVE-2", "curl", finding.SeverityLow, "3")}
	n.process(ctx, facts(), scan2, complete, "", "")
	if len(a.msgs) != 2 || len(a.msgs[1].New) != 1 || a.msgs[1].New[0].CVE != "CVE-3" {
		t.Fatalf("new: %+v", a.msgs[len(a.msgs)-1])
	}
	scan3 := []finding.Finding{cveF("CVE-1", "openssl", finding.SeverityCritical, "2"), cveF("CVE-3", "bash", finding.SeverityHigh, "5.2")}
	n.process(ctx, facts(), scan3, complete, "", "")
	if m := a.msgs[len(a.msgs)-1]; len(m.FixAvailable) != 1 || len(m.New) != 0 || len(m.Resolved) != 0 {
		t.Fatalf("fix available: %+v", m)
	}
	// Lookups failed: missing CVE findings are NOT reported as resolved.
	n.process(ctx, facts(), nil, &feed.ScanSources{Complete: false, IncompleteReasons: []string{"osv down"}}, "", "")
	if len(a.msgs) != 3 {
		t.Fatalf("incomplete scan produced a message: %+v", a.msgs[len(a.msgs)-1])
	}
	// Complete again without CVE-1: resolved, once.
	n.process(ctx, facts(), scan3[1:], complete, "", "")
	if m := a.msgs[len(a.msgs)-1]; len(m.Resolved) != 1 || m.Resolved[0].CVE != "CVE-1" || m.Resolved[0].Package != "openssl" {
		t.Fatalf("resolved: %+v", m)
	}
	// Channel b failed every time: it keeps retrying its baseline, and
	// once it works it gets the baseline (current state), not a backlog.
	b.fail = false
	n.process(ctx, facts(), scan3[1:], complete, "", "")
	if len(b.msgs) != 1 || b.msgs[0].Event != "baseline" {
		t.Fatalf("b: %+v", b.msgs)
	}
	if len(a.msgs) != 4 {
		t.Errorf("a got a duplicate after b recovered: %d", len(a.msgs))
	}
}

func TestDigest(t *testing.T) {
	a := &recorder{name: "a"}
	n := newTestNotifier(t, a)
	n.cfg.Digest = time.Hour
	clock := time.Now()
	n.now = func() time.Time { return clock }
	fs := []finding.Finding{cveF("CVE-1", "openssl", finding.SeverityHigh, "2")}
	n.process(context.Background(), facts(), fs, nil, "", "")
	n.process(context.Background(), facts(), fs, nil, "", "")
	clock = clock.Add(2 * time.Hour)
	n.process(context.Background(), facts(), fs, nil, "", "")
	if len(a.msgs) != 2 || a.msgs[1].Event != "digest" || len(a.msgs[1].Current) != 1 {
		t.Errorf("msgs = %d, last %+v", len(a.msgs), a.msgs[len(a.msgs)-1])
	}
}

func sampleMessage() *Message {
	m := baseMessage(facts(), []finding.Finding{cveF("CVE-1", "libssl3:amd64", finding.SeverityCritical, "3.0.17")}, &feed.ScanSources{Complete: false, IncompleteReasons: []string{"nvd: 2 lookups failed"}}, "/r.json", "/r.pdf", "high", time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	m.Event = "changes"
	m.New = []finding.Finding{cveF("CVE-1", "libssl3:amd64", finding.SeverityCritical, "3.0.17")}
	m.Resolved = []finding.Finding{{ID: "x", Title: "old", Severity: finding.SeverityHigh}}
	return m
}

func TestTextAndHTML(t *testing.T) {
	m := sampleMessage()
	txt, html := m.Text(), m.HTML()
	for _, want := range []string{"1 new, 1 resolved (worst: Critical)", "CVE-1 in libssl3:amd64", "apt-get install --only-upgrade libssl3", "incomplete", "/r.pdf"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text lacks %q:\n%s", want, txt)
		}
	}
	if !strings.Contains(html, "<h3") || !strings.Contains(html, "apt-get install --only-upgrade libssl3") || strings.Contains(html, "<script") {
		t.Errorf("html = %s", html)
	}
}

func TestGenericWebhookSignature(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secretFile, []byte("s3cret\n"), 0o600)
	var got Payload
	var sigOK bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts := r.Header.Get(HeaderTimestamp)
		sigOK = r.Header.Get(HeaderSignature) == Sign("s3cret", ts, body) && r.Header.Get(HeaderEvent) == "changes"
		json.Unmarshal(body, &got)
	}))
	defer srv.Close()
	w := newWebhook(config.WebhookConfig{Type: "generic", URL: srv.URL, SecretFile: secretFile}, 0, "test")
	if err := w.Send(context.Background(), sampleMessage()); err != nil {
		t.Fatal(err)
	}
	if !sigOK {
		t.Error("signature did not verify")
	}
	if got.Schema != "lync.notification/v1" || got.Event != "changes" || len(got.New) != 1 || got.New[0].CVE != "CVE-1" ||
		got.Counts["critical"] != 1 || got.DataSources == nil || got.DataSources.Complete || len(got.Commands) != 1 {
		t.Errorf("payload = %+v", got)
	}
}

func TestChatPayloadShapes(t *testing.T) {
	bodies := map[string]map[string]any{}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v map[string]any
		json.NewDecoder(r.Body).Decode(&v)
		mu.Lock()
		bodies[r.URL.Path] = v
		mu.Unlock()
		if r.Header.Get(HeaderSignature) != "" {
			t.Error("chat webhooks must not carry the generic signature")
		}
	}))
	defer srv.Close()
	for _, typ := range []string{"slack", "discord", "teams"} {
		w := newWebhook(config.WebhookConfig{Type: typ, URL: srv.URL + "/" + typ}, 0, "test")
		if err := w.Send(context.Background(), sampleMessage()); err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
	}
	s := bodies["/slack"]
	if s["text"] == "" || len(s["blocks"].([]any)) != 3 {
		t.Errorf("slack = %v", s)
	}
	d := bodies["/discord"]
	emb := d["embeds"].([]any)[0].(map[string]any)
	if !strings.Contains(emb["description"].(string), "**New (1)**") || emb["color"].(float64) != 0xb00020 {
		t.Errorf("discord = %v", d)
	}
	tm := bodies["/teams"]
	att := tm["attachments"].([]any)[0].(map[string]any)
	card := att["content"].(map[string]any)
	if tm["type"] != "message" || att["contentType"] != "application/vnd.microsoft.card.adaptive" || card["type"] != "AdaptiveCard" || len(card["body"].([]any)) < 4 {
		t.Errorf("teams = %v", tm)
	}
}

func TestWebhookRetryAndNoURLInErrors(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n < 3 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	w := newWebhook(config.WebhookConfig{Type: "slack", URL: srv.URL + "/services/T000/B000/SECRETTOKEN"}, 0, "test")
	w.backoff = time.Millisecond
	if err := w.Send(context.Background(), sampleMessage()); err != nil || n != 3 {
		t.Fatalf("err=%v attempts=%d", err, n)
	}
	w.cfg.URL = "http://127.0.0.1:1/services/T000/B000/SECRETTOKEN"
	err := w.Send(context.Background(), sampleMessage())
	if err == nil || strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Errorf("error leaks the webhook URL: %v", err)
	}
	w.cfg.URL = srv.URL + "/x"
	n = 0
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n++; w.WriteHeader(400) })
	if err := w.Send(context.Background(), sampleMessage()); err == nil || n != 1 {
		t.Errorf("4xx must not be retried: n=%d err=%v", n, err)
	}
}

// --- fake SMTP server -----------------------------------------------------------

type smtpSession struct {
	auth string
	from string
	rcpt []string
	data string
	tls  bool
}

func fakeSMTP(t *testing.T, tlsCfg *tls.Config, implicit bool) (string, chan smtpSession) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	out := make(chan smtpSession, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var s smtpSession
		if implicit {
			conn = tls.Server(conn, tlsCfg)
			s.tls = true
		}
		r, w := bufio.NewReader(conn), bufio.NewWriter(conn)
		say := func(l string) { w.WriteString(l + "\r\n"); w.Flush() }
		say("220 fake ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
			switch cmd {
			case "EHLO", "HELO":
				ext := []string{"250-fake", "250-AUTH PLAIN"}
				if tlsCfg != nil && !s.tls {
					ext = append(ext, "250-STARTTLS")
				}
				for _, e := range ext {
					say(e)
				}
				say("250 OK")
			case "STARTTLS":
				say("220 go ahead")
				tc := tls.Server(conn, tlsCfg)
				if err := tc.Handshake(); err != nil {
					return
				}
				conn = tc
				r, w = bufio.NewReader(conn), bufio.NewWriter(conn)
				s.tls = true
			case "AUTH":
				s.auth = line
				say("235 ok")
			case "MAIL":
				s.from = line
				say("250 ok")
			case "RCPT":
				s.rcpt = append(s.rcpt, line)
				say("250 ok")
			case "DATA":
				say("354 go")
				var b strings.Builder
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				s.data = b.String()
				say("250 queued")
			case "QUIT":
				say("221 bye")
				out <- s
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().String(), out
}

func selfSigned(t *testing.T) (*tls.Config, *x509.CertPool) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

func emailCfg(addr, mode string, pwFile string) config.EmailConfig {
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	return config.EmailConfig{Enabled: true, Host: host, Port: p, TLS: mode, Username: "lync", PasswordFile: pwFile,
		From: "Lync <lync@example.test>", To: []string{"ops@example.test", "sec@example.test"}, AttachPDF: true}
}

func TestEmailSTARTTLSAuthAttachment(t *testing.T) {
	srvTLS, pool := selfSigned(t)
	addr, got := fakeSMTP(t, srvTLS, false)
	dir := t.TempDir()
	pw := filepath.Join(dir, "pw")
	os.WriteFile(pw, []byte("hunter2\n"), 0o600)
	pdf := filepath.Join(dir, "lync-report.pdf")
	os.WriteFile(pdf, []byte("%PDF-1.4 fake"), 0o600)
	e := newEmail(emailCfg(addr, "starttls", pw))
	e.tlsConfig = &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}
	m := sampleMessage()
	m.ReportPDF = pdf
	if err := e.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	s := <-got
	if !s.tls || !strings.HasPrefix(s.auth, "AUTH PLAIN") || s.from != "MAIL FROM:<lync@example.test>" || len(s.rcpt) != 2 {
		t.Errorf("session = %+v", s)
	}
	for _, want := range []string{"multipart/mixed", "multipart/alternative", "text/plain", "text/html", "application/pdf", "lync-report.pdf", "Subject: "} {
		if !strings.Contains(s.data, want) {
			t.Errorf("message lacks %q", want)
		}
	}
	if strings.Contains(s.data, "hunter2") {
		t.Error("password in message")
	}
}

func TestEmailImplicitTLS(t *testing.T) {
	srvTLS, pool := selfSigned(t)
	addr, got := fakeSMTP(t, srvTLS, true)
	pw := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(pw, []byte("pw"), 0o600)
	e := newEmail(emailCfg(addr, "tls", pw))
	e.tlsConfig = &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}
	if err := e.Send(context.Background(), sampleMessage()); err != nil {
		t.Fatal(err)
	}
	if s := <-got; !s.tls || s.data == "" {
		t.Errorf("session = %+v", s)
	}
}

func TestEmailRefusesPlaintextWithoutSTARTTLS(t *testing.T) {
	addr, _ := fakeSMTP(t, nil, false)
	e := newEmail(emailCfg(addr, "starttls", ""))
	e.cfg.Username = ""
	if err := e.Send(context.Background(), sampleMessage()); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("err = %v", err)
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(config.NotifyConfig{Enabled: true, StateFile: "x"}, "v", quiet); err == nil {
		t.Error("no channels should fail")
	}
	if _, err := New(config.NotifyConfig{Enabled: true, StateFile: "x", Webhooks: []config.WebhookConfig{{Type: "irc", URL: "http://x"}}}, "v", quiet); err == nil {
		t.Error("bad type should fail")
	}
	n, err := New(config.NotifyConfig{Enabled: true, StateFile: "x", Webhooks: []config.WebhookConfig{{Type: "slack", URLEnv: "LYNC_TEST_HOOK", Name: "ops"}}}, "v", quiet)
	if err != nil || n.Channels()[0] != "webhook:ops (slack)" {
		t.Errorf("n=%v err=%v", n, err)
	}
}
