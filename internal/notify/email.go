package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ryan785/lync/internal/config"
)

const maxAttachment = 10 << 20

type email struct {
	cfg       config.EmailConfig
	tlsConfig *tls.Config // nil = system roots, ServerName = host (tests inject one)
	now       func() time.Time
}

func newEmail(cfg config.EmailConfig) *email {
	return &email{cfg: cfg, now: time.Now}
}

func (e *email) Name() string { return "email" }

func (e *email) port() int {
	if e.cfg.Port > 0 {
		return e.cfg.Port
	}
	switch e.cfg.TLS {
	case "tls":
		return 465
	case "none":
		return 25
	}
	return 587
}

func (e *email) tlsConf() *tls.Config {
	if e.tlsConfig != nil {
		return e.tlsConfig
	}
	return &tls.Config{ServerName: e.cfg.Host, MinVersion: tls.VersionTLS12}
}

// Send delivers one message. The password is read from password_file or
// password_env at send time and is never logged or included in errors.
func (e *email) Send(ctx context.Context, m *Message) error {
	msg, err := e.build(m)
	if err != nil {
		return err
	}
	timeout := e.cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < timeout {
		timeout = time.Until(dl)
	}
	addr := net.JoinHostPort(e.cfg.Host, strconv.Itoa(e.port()))
	d := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	if e.cfg.TLS == "tls" {
		conn, err = tls.DialWithDialer(d, "tcp", addr, e.tlsConf())
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp connect %s: %w", addr, err)
	}
	conn.SetDeadline(time.Now().Add(timeout))
	c, err := smtp.NewClient(conn, e.cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp: %w", err)
	}
	defer c.Close()
	if e.cfg.TLS == "" || e.cfg.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp: server does not offer STARTTLS (set notify.email.tls: none only for a local relay)")
		}
		if err := c.StartTLS(e.tlsConf()); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if e.cfg.Username != "" {
		pw, err := readSecret(e.cfg.PasswordFile, e.cfg.PasswordEnv)
		if err != nil {
			return fmt.Errorf("smtp password: %w", err)
		}
		if err := c.Auth(smtp.PlainAuth("", e.cfg.Username, pw, e.cfg.Host)); err != nil {
			return fmt.Errorf("smtp auth as %s failed: %s", e.cfg.Username, scrub(err.Error(), pw))
		}
	}
	if err := c.Mail(addrOnly(e.cfg.From)); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, to := range e.cfg.To {
		if err := c.Rcpt(addrOnly(to)); err != nil {
			return fmt.Errorf("smtp RCPT TO %s: %w", to, err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		wc.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp: message rejected: %w", err)
	}
	return c.Quit()
}

func scrub(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "[REDACTED]")
}

// addrOnly: "Lync <lync@example.com>" -> "lync@example.com".
func addrOnly(a string) string {
	if i := strings.LastIndex(a, "<"); i >= 0 {
		if j := strings.LastIndex(a, ">"); j > i {
			return a[i+1 : j]
		}
	}
	return strings.TrimSpace(a)
}

func boundary() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "lync-" + hex.EncodeToString(b)
}

func qp(s string) string {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	w.Write([]byte(s))
	w.Close()
	return buf.String()
}

// build renders a MIME message: multipart/alternative (text + HTML),
// wrapped in multipart/mixed when the PDF report is attached.
func (e *email) build(m *Message) ([]byte, error) {
	var b bytes.Buffer
	h := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	h("From", e.cfg.From)
	h("To", strings.Join(e.cfg.To, ", "))
	h("Subject", mime.QEncoding.Encode("utf-8", m.Subject()))
	h("Date", e.now().Format(time.RFC1123Z))
	h("MIME-Version", "1.0")
	h("X-Lync-Event", m.Event)
	alt := boundary()
	var attach []byte
	if e.cfg.AttachPDF && m.ReportPDF != "" {
		if fi, err := os.Stat(m.ReportPDF); err == nil && fi.Size() <= maxAttachment {
			attach, _ = os.ReadFile(m.ReportPDF)
		}
	}
	mixed := ""
	if attach != nil {
		mixed = boundary()
		h("Content-Type", `multipart/mixed; boundary="`+mixed+`"`)
		b.WriteString("\r\n--" + mixed + "\r\n")
	}
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", alt)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n%s\r\n", alt, qp(m.Text()))
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n%s\r\n", alt, qp(m.HTML()))
	fmt.Fprintf(&b, "--%s--\r\n", alt)
	if attach != nil {
		name := filepath.Base(m.ReportPDF)
		fmt.Fprintf(&b, "--%s\r\nContent-Type: application/pdf; name=\"%s\"\r\nContent-Disposition: attachment; filename=\"%s\"\r\nContent-Transfer-Encoding: base64\r\n\r\n", mixed, name, name)
		enc := base64.StdEncoding.EncodeToString(attach)
		for len(enc) > 76 {
			b.WriteString(enc[:76] + "\r\n")
			enc = enc[76:]
		}
		b.WriteString(enc + "\r\n")
		fmt.Fprintf(&b, "--%s--\r\n", mixed)
	}
	return b.Bytes(), nil
}
