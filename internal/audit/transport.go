package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Transport is an http.RoundTripper that, for every request:
//   - buffers the whole response body, so a connection reset or HTTP/2
//     stream error *mid-body* (NVD: "stream error: stream ID 1;
//     INTERNAL_ERROR") is retried like any other transient failure;
//   - retries transport errors and 429/500/502/503/504 with exponential
//     backoff (honouring Retry-After up to MaxBackoff);
//   - after H2FallbackAfter HTTP/2-flavoured failures, switches the rest of
//     the run to HTTP/1.1;
//   - logs one FETCH line per request (method, redacted URL, status, bytes,
//     duration, attempts, protocol).
//
// Only requests that can be replayed are retried (no body, or GetBody set).
type Transport struct {
	Base            *http.Transport
	MaxAttempts     int           // default 5
	InitialBackoff  time.Duration // default 1s
	MaxBackoff      time.Duration // default 30s
	H2FallbackAfter int           // default 2
	MaxBody         int64         // default 1GB
	// AttemptTimeout bounds one attempt (headers + whole body), so a hung
	// request is retried instead of eating the caller's whole
	// http.Client.Timeout (NVD can stall for minutes). Default 3m.
	AttemptTimeout time.Duration
	Sleep          func(ctx context.Context, d time.Duration) error

	mu       sync.Mutex
	h1       *http.Transport
	h2errs   int
	fellBack bool
}

// NewTransport wraps a clone of http.DefaultTransport.
func NewTransport() *Transport {
	base := http.DefaultTransport.(*http.Transport).Clone()
	return &Transport{Base: base}
}

func (t *Transport) defaults() {
	if t.MaxAttempts <= 0 {
		t.MaxAttempts = 5
	}
	if t.InitialBackoff <= 0 {
		t.InitialBackoff = time.Second
	}
	if t.MaxBackoff <= 0 {
		t.MaxBackoff = 30 * time.Second
	}
	if t.H2FallbackAfter <= 0 {
		t.H2FallbackAfter = 2
	}
	if t.AttemptTimeout <= 0 {
		t.AttemptTimeout = 3 * time.Minute
	}
	if t.MaxBody <= 0 {
		t.MaxBody = 1 << 30
	}
	if t.Sleep == nil {
		t.Sleep = func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		}
	}
}

func (t *Transport) current() http.RoundTripper {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fellBack {
		if t.h1 == nil {
			h1 := t.Base.Clone()
			h1.ForceAttemptHTTP2 = false
			h1.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
			// Advertise only http/1.1 in ALPN, or the server picks h2 again.
			if h1.TLSClientConfig != nil {
				h1.TLSClientConfig = h1.TLSClientConfig.Clone()
			} else {
				h1.TLSClientConfig = &tls.Config{}
			}
			h1.TLSClientConfig.NextProtos = []string{"http/1.1"}
			t.h1 = h1
		}
		return t.h1
	}
	return t.Base
}

func isH2Error(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "stream error") || strings.Contains(s, "http2:") ||
		strings.Contains(s, "INTERNAL_ERROR") || strings.Contains(s, "PROTOCOL_ERROR") || strings.Contains(s, "GOAWAY")
}

func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.defaults()
	start := time.Now()
	replayable := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
	backoff := t.InitialBackoff
	var lastErr error
	var lastStatus int
	for attempt := 1; attempt <= t.MaxAttempts; attempt++ {
		actx, cancel := context.WithTimeout(req.Context(), t.AttemptTimeout)
		r := req.Clone(actx)
		if attempt > 1 && req.GetBody != nil {
			b, err := req.GetBody()
			if err != nil {
				cancel()
				return nil, err
			}
			r.Body = b
		}
		resp, err := t.current().RoundTrip(r)
		if err == nil && retryableStatus(resp.StatusCode) && attempt < t.MaxAttempts && replayable {
			lastStatus = resp.StatusCode
			wait := backoff
			if ra, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && ra > 0 {
				wait = time.Duration(ra) * time.Second
			}
			if wait > t.MaxBackoff {
				wait = t.MaxBackoff
			}
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			cancel()
			Log("RETRY", "%s %s status=%d attempt=%d wait=%s", req.Method, req.URL.Redacted(), resp.StatusCode, attempt, wait)
			if serr := t.Sleep(req.Context(), wait); serr != nil {
				return nil, serr
			}
			backoff *= 2
			continue
		}
		if err == nil {
			var body []byte
			body, err = io.ReadAll(io.LimitReader(resp.Body, t.MaxBody))
			resp.Body.Close()
			cancel()
			if err == nil {
				resp.Body = io.NopCloser(bytes.NewReader(body))
				resp.ContentLength = int64(len(body))
				Log("FETCH", "%s %s status=%d bytes=%s dur=%s attempts=%d proto=%s",
					req.Method, req.URL.Redacted(), resp.StatusCode, Size(int64(len(body))),
					time.Since(start).Round(time.Millisecond), attempt, resp.Proto)
				return resp, nil
			}
			// fall through: mid-body failure is retried below
		}
		cancel()
		lastErr = err
		// A per-attempt timeout (actx) is retryable; the caller's own
		// context ending is not.
		if req.Context().Err() != nil || !replayable || permanentError(err) {
			break
		}
		if isH2Error(err) {
			t.mu.Lock()
			t.h2errs++
			if !t.fellBack && t.h2errs >= t.H2FallbackAfter {
				t.fellBack = true
				t.mu.Unlock()
				Log("HTTP", "switching to HTTP/1.1 after %d HTTP/2 errors", t.H2FallbackAfter)
			} else {
				t.mu.Unlock()
			}
		}
		if attempt == t.MaxAttempts {
			break
		}
		wait := backoff
		if wait > t.MaxBackoff {
			wait = t.MaxBackoff
		}
		Log("RETRY", "%s %s error=%q attempt=%d wait=%s", req.Method, req.URL.Redacted(), err.Error(), attempt, wait)
		if serr := t.Sleep(req.Context(), wait); serr != nil {
			return nil, serr
		}
		backoff *= 2
	}
	if lastErr == nil && lastStatus != 0 {
		lastErr = errors.New("retries exhausted, last status " + strconv.Itoa(lastStatus))
	}
	Log("FETCH", "%s %s FAILED error=%q dur=%s", req.Method, req.URL.Redacted(), errString(lastErr), time.Since(start).Round(time.Millisecond))
	return nil, lastErr
}

func errString(err error) string {
	if err == nil {
		return "unknown"
	}
	return err.Error()
}

// permanentError: failures a retry cannot fix (TLS trust, DNS name not
// found), so the run fails fast and the log says why.
func permanentError(err error) bool {
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	var dns *net.DNSError
	if errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci) {
		return true
	}
	if errors.As(err, &dns) && dns.IsNotFound {
		return true
	}
	return strings.Contains(err.Error(), "x509: ")
}
