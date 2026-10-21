package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/config"
	"github.com/ryan785/lync/internal/finding"
)

// Signature headers on generic webhooks (when a secret is configured):
//
//	X-Lync-Timestamp:     unix seconds
//	X-Lync-Signature-256: "sha256=" + hex(HMAC-SHA256(secret, timestamp + "." + body))
const (
	HeaderEvent     = "X-Lync-Event"
	HeaderTimestamp = "X-Lync-Timestamp"
	HeaderSignature = "X-Lync-Signature-256"
)

// Sign computes the signature header value for a generic webhook body.
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

type webhook struct {
	cfg     config.WebhookConfig
	name    string
	version string
	client  *http.Client
	retries int
	backoff time.Duration
	now     func() time.Time
}

func newWebhook(cfg config.WebhookConfig, i int, version string) *webhook {
	name := cfg.Name
	if name == "" {
		name = fmt.Sprintf("%s-%d", cfg.Type, i)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	// A plain transport, not the audit one: webhook URLs embed tokens
	// (Slack, Discord, Teams) and must never reach a log line.
	return &webhook{cfg: cfg, name: name, version: version, retries: 3, backoff: 2 * time.Second, now: time.Now,
		client: &http.Client{Timeout: timeout, Transport: plainTransport()}}
}

func plainTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
}

func (w *webhook) Name() string { return "webhook:" + w.name + " (" + w.cfg.Type + ")" }

func (w *webhook) url() (string, error) {
	if w.cfg.URL != "" {
		return w.cfg.URL, nil
	}
	u, err := readSecret(w.cfg.URLFile, w.cfg.URLEnv)
	if err == nil && u == "" {
		err = errors.New("webhook URL is empty")
	}
	return u, err
}

func (w *webhook) Send(ctx context.Context, m *Message) error {
	target, err := w.url()
	if err != nil {
		return err
	}
	var body []byte
	switch w.cfg.Type {
	case "slack":
		body, err = json.Marshal(slackPayload(m))
	case "discord":
		body, err = json.Marshal(discordPayload(m))
	case "teams":
		body, err = json.Marshal(teamsPayload(m))
	default:
		body, err = json.Marshal(m.Payload())
	}
	if err != nil {
		return err
	}
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("User-Agent", "lync/"+w.version)
	if w.cfg.Type == "generic" {
		ts := strconv.FormatInt(w.now().Unix(), 10)
		hdr.Set(HeaderEvent, m.Event)
		hdr.Set(HeaderTimestamp, ts)
		secret, err := readSecret(w.cfg.SecretFile, w.cfg.SecretEnv)
		if err != nil {
			return err
		}
		if secret != "" {
			hdr.Set(HeaderSignature, Sign(secret, ts, body))
		}
	}
	return postWithRetry(ctx, w.client, target, hdr, body, w.retries, w.backoff)
}

// postWithRetry POSTs body, retrying network errors, 429 and 5xx. Errors
// never contain the URL (it may hold a token).
func postWithRetry(ctx context.Context, c *http.Client, target string, hdr http.Header, body []byte, attempts int, backoff time.Duration) error {
	host := "webhook"
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Host
	}
	var last error
	for i := 1; i <= attempts; i++ {
		req, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("%s: invalid webhook URL", host)
		}
		req.Header = hdr.Clone()
		resp, err := c.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			last = fmt.Errorf("%s: %v", host, err)
		} else {
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			last = fmt.Errorf("%s: http %d %s", host, resp.StatusCode, strings.TrimSpace(string(snippet)))
			if resp.StatusCode != 429 && resp.StatusCode < 500 {
				return last
			}
			if ra, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && ra > 0 && ra < 60 {
				backoff = time.Duration(ra) * time.Second
			}
		}
		if i < attempts {
			select {
			case <-ctx.Done():
				return last
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	}
	return last
}

// --- chat formatters -----------------------------------------------------------

const chatItems = 15

func chatLines(m *Message) []string {
	var out []string
	add := func(title string, fs []finding.Finding) {
		if len(fs) == 0 {
			return
		}
		out = append(out, fmt.Sprintf("*%s (%d)*", title, len(fs)))
		for i, f := range fs {
			if i == chatItems {
				out = append(out, fmt.Sprintf("... and %d more", len(fs)-chatItems))
				break
			}
			out = append(out, "- "+itemLine(f))
		}
	}
	add("New", m.New)
	add("Fix now available", m.FixAvailable)
	add("Resolved", m.Resolved)
	add("Open", m.Current)
	return out
}

func chatBody(m *Message, bold func(string) string) string {
	if m.Event == "test" {
		return "Test notification from Lync: this channel works."
	}
	var b strings.Builder
	if n := incompleteNote(m.Sources); n != "" {
		b.WriteString(bold(n) + "\n")
	}
	for _, l := range chatLines(m) {
		if strings.HasPrefix(l, "*") {
			l = bold(strings.Trim(l, "*"))
		}
		b.WriteString(l + "\n")
	}
	if cmds := remediationCommands(m.manager, m.actionable()); len(cmds) > 0 {
		b.WriteString("```\n" + strings.Join(cmds, "\n") + "\n```\n")
	}
	b.WriteString(countsLine(m.Counts, m.Total))
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-20] + "\n... (truncated)"
}

func slackPayload(m *Message) map[string]any {
	text := truncate(chatBody(m, func(s string) string { return "*" + s + "*" }), 2900)
	return map[string]any{
		"text": m.Subject(),
		"blocks": []any{
			map[string]any{"type": "header", "text": map[string]any{"type": "plain_text", "text": truncate(m.Subject(), 150)}},
			map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": text}},
			map[string]any{"type": "context", "elements": []any{map[string]any{"type": "mrkdwn",
				"text": fmt.Sprintf("%s · %s · %s", m.Host, m.OS, m.Generated.UTC().Format(time.RFC3339))}}},
		},
	}
}

func worstColor(m *Message) int {
	worst := finding.SeverityUnknown
	for _, fs := range [][]finding.Finding{m.New, m.FixAvailable, m.Current} {
		for _, f := range fs {
			if f.Severity.Rank() > worst.Rank() {
				worst = f.Severity
			}
		}
	}
	if m.Event == "test" || (len(m.New)+len(m.FixAvailable)+len(m.Current) == 0) {
		return 0x2e7d32
	}
	v, _ := strconv.ParseInt(strings.TrimPrefix(sevHex[worst], "#"), 16, 32)
	return int(v)
}

func discordPayload(m *Message) map[string]any {
	desc := truncate(chatBody(m, func(s string) string { return "**" + s + "**" }), 4000)
	return map[string]any{
		"username": "Lync",
		"content":  truncate(m.Subject(), 1900),
		"embeds": []any{map[string]any{
			"title":       truncate(m.Host+" ("+m.OS+")", 250),
			"description": desc,
			"color":       worstColor(m),
			"timestamp":   m.Generated.UTC().Format(time.RFC3339),
			"footer":      map[string]any{"text": "lync " + m.Event},
		}},
	}
}

// teamsPayload is an Adaptive Card message, accepted by Teams Workflows
// ("Post to a channel when a webhook request is received") and by the
// older Office 365 connector webhooks.
func teamsPayload(m *Message) map[string]any {
	body := []any{
		map[string]any{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": true, "text": m.Subject()},
		map[string]any{"type": "TextBlock", "isSubtle": true, "wrap": true, "spacing": "None",
			"text": fmt.Sprintf("%s · %s · %s", m.Host, m.OS, m.Generated.UTC().Format(time.RFC3339))},
	}
	if n := incompleteNote(m.Sources); n != "" {
		body = append(body, map[string]any{"type": "TextBlock", "color": "Attention", "weight": "Bolder", "wrap": true, "text": n})
	}
	if m.Event == "test" {
		body = append(body, map[string]any{"type": "TextBlock", "wrap": true, "text": "Test notification from Lync: this channel works."})
	}
	for _, l := range chatLines(m) {
		tb := map[string]any{"type": "TextBlock", "wrap": true, "spacing": "None", "text": l}
		if strings.HasPrefix(l, "*") {
			tb["text"] = strings.Trim(l, "*")
			tb["weight"] = "Bolder"
			tb["spacing"] = "Medium"
		}
		body = append(body, tb)
	}
	if cmds := remediationCommands(m.manager, m.actionable()); len(cmds) > 0 {
		body = append(body, map[string]any{"type": "TextBlock", "wrap": true, "fontType": "Monospace", "text": strings.Join(cmds, "\n\n")})
	}
	body = append(body, map[string]any{"type": "TextBlock", "isSubtle": true, "wrap": true, "text": countsLine(m.Counts, m.Total)})
	return map[string]any{
		"type": "message",
		"attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"body":    body,
			},
		}},
	}
}
