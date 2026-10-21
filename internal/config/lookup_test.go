package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFeedModeDefaultsToLookup(t *testing.T) {
	c := Default()
	if c.FeedMode() != "lookup" || !c.Feed.LocalCheck || c.Feed.LocalRefresh || c.Notify.Enabled || !c.Inventory.Enabled || c.Inventory.Containers {
		t.Errorf("defaults: %+v %+v %+v", c.Feed, c.Notify, c.Inventory)
	}
	if c.Scan.Interval != 6*time.Hour || !c.Scan.OnPackageChange {
		t.Errorf("scan defaults: %+v", c.Scan)
	}
	c.Feed.Mode = "bulk"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "feed.mode") {
		t.Errorf("bad mode accepted: %v", err)
	}
}

func TestNotifyConfigParsesAndValidates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lync.yaml")
	body := `feed:
  mode: full
notify:
  enabled: true
  min_severity: medium
  digest: 24h
  email:
    enabled: true
    host: smtp.example.com
    username: lync
    password_file: /etc/lync/smtp.pass
    from: lync@example.com
    to: [ops@example.com]
    attach_pdf: true
  webhooks:
    - name: ops
      type: slack
      url_file: /etc/lync/slack.url
    - type: generic
      url: https://hooks.example.com/lync
      secret_file: /etc/lync/hook.secret
inventory:
  containers: true
  roots: [/srv/app]
`
	os.WriteFile(p, []byte(body), 0o644)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.FeedMode() != "full" || c.Notify.Digest != 24*time.Hour || len(c.Notify.Webhooks) != 2 || !c.Notify.Email.AttachPDF ||
		!c.Inventory.Enabled || !c.Inventory.Containers || c.Inventory.Roots[0] != "/srv/app" {
		t.Errorf("parsed: %+v", c)
	}
	bad := []string{
		"notify:\n  enabled: true\n  min_severity: urgent\n",
		"notify:\n  enabled: true\n  webhooks: [{type: slack}]\n",
		"notify:\n  enabled: true\n  email: {enabled: true, host: x}\n",
		"notify:\n  enabled: true\n  email: {enabled: true, host: x, from: a, to: [b], tls: ssl}\n",
		"notify:\n  enabled: true\n  events: [everything]\n",
	}
	for _, b := range bad {
		os.WriteFile(p, []byte(b), 0o644)
		if _, err := Load(p); err == nil {
			t.Errorf("accepted:\n%s", b)
		}
	}
}
