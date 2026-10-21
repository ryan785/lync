package audit

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// capture enables audit logging into a buffer for the test's duration.
func capture(t *testing.T) *syncBuf {
	t.Helper()
	b := &syncBuf{}
	Enable(b)
	t.Cleanup(func() { Enable(nil) })
	return b
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func noSleep(ctx context.Context, d time.Duration) error { return nil }

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"GET https://x/?apiKey=abc123&x=1":                      "GET https://x/?apiKey=[REDACTED]&x=1",
		"Authorization: Bearer ghp_aaaaaaaaaaaaaaaaaaaaaaaa":    "Authorization: Bearer [REDACTED]",
		"LYNC_GH_TOKEN=github_pat_11AAAAAAAAAAAAAAAAAAAAAA_bbb": "LYNC_GH_TOKEN=[REDACTED]",
		"token ghs_cccccccccccccccccccccccc used":               "token [REDACTED] used",
		"password: hunter2":                                     "password: [REDACTED]",
		"rpm -qa --qf '%{NAME}'":                                "rpm -qa --qf '%{NAME}'",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOutputLogsCommand(t *testing.T) {
	buf := capture(t)
	_, err := Output(context.Background(), time.Second, "lync-definitely-missing-tool", "--flag", "a b")
	if err == nil {
		t.Fatal("expected error for missing tool")
	}
	line := buf.String()
	if !strings.Contains(line, "CMD") || !strings.Contains(line, "lync-definitely-missing-tool --flag 'a b' exit=127") {
		t.Errorf("log line = %q", line)
	}
}

func TestLogDisabledIsNoop(t *testing.T) {
	Enable(nil)
	Log("X", "nothing %d", 1) // must not panic
	if Enabled() {
		t.Error("should be disabled")
	}
}

func TestTransportRetriesStatus(t *testing.T) {
	buf := capture(t)
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, "ok-body")
	}))
	defer srv.Close()
	tr := &Transport{Base: http.DefaultTransport.(*http.Transport).Clone(), Sleep: noSleep}
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL + "/feed?apiKey=SECRET")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok-body" || atomic.LoadInt32(&n) != 3 {
		t.Errorf("body=%q requests=%d", body, n)
	}
	log := buf.String()
	if strings.Count(log, "RETRY") != 2 || !strings.Contains(log, "attempts=3") || strings.Contains(log, "SECRET") {
		t.Errorf("log:\n%s", log)
	}
}

func TestTransportGivesUp(t *testing.T) {
	capture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	tr := &Transport{Base: http.DefaultTransport.(*http.Transport).Clone(), Sleep: noSleep, MaxAttempts: 3}
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	// Last attempt returns the 502 to the caller (sources report "http 502").
	if err != nil || resp.StatusCode != http.StatusBadGateway {
		t.Errorf("resp=%v err=%v", resp, err)
	}
}

func TestTransportNoRetryOn404(t *testing.T) {
	capture(t)
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	tr := &Transport{Base: http.DefaultTransport.(*http.Transport).Clone(), Sleep: noSleep}
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	if err != nil || resp.StatusCode != 404 || n != 1 {
		t.Errorf("404 should not be retried: n=%d err=%v", n, err)
	}
}

// TestTransportHTTP2StreamResetFallback reproduces the NVD failure: the
// server resets the HTTP/2 stream mid-body (INTERNAL_ERROR). The transport
// must retry, switch to HTTP/1.1 after two such errors, and succeed.
func TestTransportHTTP2StreamResetFallback(t *testing.T) {
	buf := capture(t)
	var n int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			atomic.AddInt32(&n, 1)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"partial":`)
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler) // RST_STREAM INTERNAL_ERROR
		}
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	base := srv.Client().Transport.(*http.Transport).Clone()
	base.ForceAttemptHTTP2 = true
	tr := &Transport{Base: base, Sleep: noSleep}
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL + "/rest/json/cves/2.0")
	if err != nil {
		t.Fatalf("expected success after HTTP/1.1 fallback, got %v\nlog:\n%s", err, buf.String())
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"vulnerabilities":[]}` || resp.ProtoMajor != 1 {
		t.Errorf("proto=%s body=%q", resp.Proto, body)
	}
	if atomic.LoadInt32(&n) != 2 || !strings.Contains(buf.String(), "switching to HTTP/1.1") {
		t.Errorf("h2 attempts=%d log:\n%s", n, buf.String())
	}
}

func TestQuote(t *testing.T) {
	if got := Quote("rpm", []string{"-qa", "--qf", "%{NAME}|%{VERSION}\\n"}); got != `rpm -qa --qf '%{NAME}|%{VERSION}\n'` {
		t.Errorf("Quote = %s", got)
	}
}

func TestTransportNoRetryOnUntrustedCert(t *testing.T) {
	buf := capture(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	tr := &Transport{Base: http.DefaultTransport.(*http.Transport).Clone(), Sleep: noSleep}
	if _, err := (&http.Client{Transport: tr}).Get(srv.URL); err == nil {
		t.Fatal("expected x509 error")
	}
	if strings.Contains(buf.String(), "RETRY") {
		t.Errorf("x509 errors must not be retried:\n%s", buf.String())
	}
}

func TestTransportRetriesHungAttempt(t *testing.T) {
	buf := capture(t)
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
			return
		}
		io.WriteString(w, "page")
	}))
	defer srv.Close()
	tr := &Transport{Base: http.DefaultTransport.(*http.Transport).Clone(), Sleep: noSleep, AttemptTimeout: 200 * time.Millisecond}
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get(srv.URL)
	if err != nil {
		t.Fatalf("hung first attempt should be retried: %v\n%s", err, buf.String())
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "page" || !strings.Contains(buf.String(), "attempts=2") {
		t.Errorf("body=%q log:\n%s", b, buf.String())
	}
}
