package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Log           LogConfig           `yaml:"log"`
	Scan          ScanConfig          `yaml:"scan"`
	Feed          FeedConfig          `yaml:"feed"`
	Report        ReportConfig        `yaml:"report"`
	IPC           IPCConfig           `yaml:"ipc"`
	Applicability ApplicabilityConfig `yaml:"applicability"`
	Rules         RulesConfig         `yaml:"rules"`
	Monitor       MonitorConfig       `yaml:"monitor"`
	Notify        NotifyConfig        `yaml:"notify"`
}

type RulesConfig struct {
	Enabled bool   `yaml:"enabled"`
	Level   string `yaml:"level"` // basic | medium | strict
	// Disable / Enable take check IDs ("php:upload-progress"), ID prefixes
	// ("docker") or rule names ("ssh-config"). Enable wins over Disable and
	// turns on default-off checks such as container:php-upload-progress.
	Disable []string `yaml:"disable"`
	Enable  []string `yaml:"enable"`
	// ImageMaxAgeDays: container:image-age threshold (default 365).
	ImageMaxAgeDays int `yaml:"image_max_age_days"`
	// WireGuardStaleDays: wireguard:stale-peer threshold (default 90).
	WireGuardStaleDays int `yaml:"wireguard_stale_days"`
	// SecretScanDirs: extra roots searched for compose/.env files.
	SecretScanDirs []string `yaml:"secret_scan_dirs"`
	// Root: read the host filesystem under this prefix (testing / mounted
	// images). Empty = "/".
	Root string `yaml:"root"`
}

type MonitorConfig struct {
	Enabled       bool                `yaml:"enabled"`
	FileIntegrity FileIntegrityConfig `yaml:"file_integrity"`
}

type FileIntegrityConfig struct {
	Enabled bool     `yaml:"enabled"`
	Paths   []string `yaml:"paths"`
}

// ApplicabilityConfig controls the post-match filter that suppresses
// findings the upstream distro has explicitly declared inapplicable or
// not-going-to-fix on this host's distro+arch combo.
type ApplicabilityConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Concurrency int      `yaml:"concurrency"`
	SuppressOn  []string `yaml:"suppress_on"` // labels: not_affected, deferred_or_wontfix
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type ScanConfig struct {
	Interval time.Duration `yaml:"interval"`
	OnStart  bool          `yaml:"on_start"`
	// OnPackageChange re-scans after the rpm/dpkg/apk database changes
	// (inotify), once PackageChangeDelay has passed without further changes.
	OnPackageChange    bool          `yaml:"on_package_change"`
	PackageChangeDelay time.Duration `yaml:"package_change_delay"`
}

type FeedConfig struct {
	// Mode: "lookup" (default) queries OSV.dev per installed package and
	// NVD / Red Hat per CVE at scan time, with small caches; "full" bulk
	// downloads every source on sync_interval (hundreds of MB).
	Mode         string          `yaml:"mode"`
	SyncInterval time.Duration   `yaml:"sync_interval"`
	CacheDir     string          `yaml:"cache_dir"`
	Sources      []FeedSourceCfg `yaml:"sources"`
	Lookup       LookupConfig    `yaml:"lookup"`
	// LocalCheck cross-checks findings against the package manager's own
	// view of pending security updates (dnf/yum updateinfo, apt-get -s),
	// read-only and from cached metadata. LocalRefresh refreshes that
	// metadata first (dnf makecache / apt-get update): opt-in, it writes
	// to the package manager's cache.
	LocalCheck   bool `yaml:"local_check"`
	LocalRefresh bool `yaml:"local_refresh"`
}

// LookupConfig tunes lookup mode.
type LookupConfig struct {
	// CacheTTL: how long NVD and Red Hat per-CVE answers are reused.
	// OSV advisories are reused while their "modified" stamp is unchanged.
	CacheTTL time.Duration `yaml:"cache_ttl"`
	// NVDMaxPerRun caps NVD requests per scan (0 = 10 without an API
	// key, 200 with one). The rest are looked up on later scans.
	NVDMaxPerRun int `yaml:"nvd_max_per_run"`
	// RedHatMaxPerRun caps Red Hat per-CVE requests per scan.
	RedHatMaxPerRun int `yaml:"redhat_max_per_run"`
}

// NotifyConfig: service-mode notifications on changes. Off by default.
type NotifyConfig struct {
	Enabled bool `yaml:"enabled"`
	// MinSeverity: critical | high | medium | low | info | unknown.
	// Findings below it never trigger a notification. Default high.
	MinSeverity string `yaml:"min_severity"`
	// Events to send: new, fix_available, resolved (default all three).
	Events []string `yaml:"events"`
	// Digest sends a summary of all current findings at this interval
	// (0 = off), independent of changes.
	Digest time.Duration `yaml:"digest"`
	// StateFile remembers what each channel has been told.
	StateFile string          `yaml:"state_file"`
	Email     EmailConfig     `yaml:"email"`
	Webhooks  []WebhookConfig `yaml:"webhooks"`
}

type EmailConfig struct {
	Enabled bool   `yaml:"enabled"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"` // default 587 (starttls), 465 (tls), 25 (none)
	// TLS: starttls (default) | tls (implicit, port 465) | none (local relay only)
	TLS          string        `yaml:"tls"`
	Username     string        `yaml:"username"`
	PasswordFile string        `yaml:"password_file"`
	PasswordEnv  string        `yaml:"password_env"`
	From         string        `yaml:"from"`
	To           []string      `yaml:"to"`
	AttachPDF    bool          `yaml:"attach_pdf"`
	Timeout      time.Duration `yaml:"timeout"`
}

type WebhookConfig struct {
	Name string `yaml:"name"`
	// Type: generic | slack | discord | teams
	Type string `yaml:"type"`
	// URL, or URLFile / URLEnv to keep chat webhook tokens out of the config.
	URL        string        `yaml:"url"`
	URLFile    string        `yaml:"url_file"`
	URLEnv     string        `yaml:"url_env"`
	SecretFile string        `yaml:"secret_file"` // generic: HMAC-SHA256 key
	SecretEnv  string        `yaml:"secret_env"`
	Timeout    time.Duration `yaml:"timeout"`
}

type FeedSourceCfg struct {
	Name    string `yaml:"name"`
	Enabled bool   `yaml:"enabled"`
	APIKey  string `yaml:"api_key,omitempty"`
}

type ReportConfig struct {
	Dir           string `yaml:"dir"`
	RetentionDays int    `yaml:"retention_days"`
}

type IPCConfig struct {
	Socket string `yaml:"socket"`
}

func Default() *Config {
	return &Config{
		Log:  LogConfig{Level: "info", Format: "logfmt"},
		Scan: ScanConfig{Interval: 6 * time.Hour, OnStart: false, OnPackageChange: true, PackageChangeDelay: 2 * time.Minute},
		Feed: FeedConfig{
			Mode:         "lookup",
			LocalCheck:   true,
			Lookup:       LookupConfig{CacheTTL: 24 * time.Hour, RedHatMaxPerRun: 500},
			SyncInterval: 6 * time.Hour,
			CacheDir:     "/var/lib/lync/feeds",
			Sources: []FeedSourceCfg{
				{Name: "redhat", Enabled: true},
				{Name: "osv", Enabled: true},
				{Name: "nvd", Enabled: true},
			},
		},
		Report: ReportConfig{Dir: "/var/lib/lync/reports"},
		IPC:    IPCConfig{Socket: "/run/lync.sock"},
		Applicability: ApplicabilityConfig{
			Enabled:     true,
			Concurrency: 5,
			SuppressOn:  []string{"not_affected", "deferred_or_wontfix"},
		},
		Rules: RulesConfig{
			Enabled: true,
			Level:   "medium",
		},
		Notify: NotifyConfig{
			MinSeverity: "high",
			Events:      []string{"new", "fix_available", "resolved"},
			StateFile:   "/var/lib/lync/notify-state.json",
		},
		Monitor: MonitorConfig{
			Enabled: true,
			FileIntegrity: FileIntegrityConfig{
				Enabled: true,
				Paths: []string{
					"/etc/ssh/sshd_config",
					"/etc/sudoers",
					"/etc/sudoers.d",
					"/etc/passwd",
					"/etc/shadow",
					"/etc/pam.d",
					"/etc/crontab",
					"/etc/cron.d",
					"/root/.ssh/authorized_keys",
				},
			},
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Validate rejects settings that would crash or silently disable the
// daemon. A zero/negative interval makes time.NewTicker panic at startup.
func (c *Config) Validate() error {
	if c.Scan.Interval <= 0 {
		return fmt.Errorf("scan.interval must be > 0 (got %s)", c.Scan.Interval)
	}
	if c.Feed.SyncInterval <= 0 {
		return fmt.Errorf("feed.sync_interval must be > 0 (got %s)", c.Feed.SyncInterval)
	}
	if c.Feed.CacheDir == "" {
		return fmt.Errorf("feed.cache_dir must be set")
	}
	if c.Report.Dir == "" {
		return fmt.Errorf("report.dir must be set")
	}
	if c.Report.RetentionDays < 0 {
		return fmt.Errorf("report.retention_days must be >= 0")
	}
	switch c.Feed.Mode {
	case "", "lookup", "full":
	default:
		return fmt.Errorf("feed.mode must be lookup or full (got %q)", c.Feed.Mode)
	}
	if c.Scan.PackageChangeDelay < 0 {
		return fmt.Errorf("scan.package_change_delay must be >= 0")
	}
	if err := c.Notify.Validate(); err != nil {
		return err
	}
	// Unknown feed source names and rules levels are deliberately tolerated
	// (feed.Build skips them; rules.ParseLevel falls back to medium) so a
	// config typo degrades coverage instead of taking the daemon down.
	return nil
}

// FeedMode returns the effective feed mode ("lookup" unless "full").
func (c *Config) FeedMode() string {
	if c.Feed.Mode == "full" {
		return "full"
	}
	return "lookup"
}

// Validate checks the notify block; only enabled channels are checked.
func (n *NotifyConfig) Validate() error {
	if !n.Enabled {
		return nil
	}
	switch strings.ToLower(n.MinSeverity) {
	case "", "critical", "high", "medium", "low", "info", "unknown":
	default:
		return fmt.Errorf("notify.min_severity: unknown severity %q", n.MinSeverity)
	}
	for _, e := range n.Events {
		switch e {
		case "new", "fix_available", "resolved":
		default:
			return fmt.Errorf("notify.events: unknown event %q (new, fix_available, resolved)", e)
		}
	}
	if n.Digest < 0 {
		return fmt.Errorf("notify.digest must be >= 0")
	}
	if n.StateFile == "" {
		return fmt.Errorf("notify.state_file must be set")
	}
	if e := n.Email; e.Enabled {
		if e.Host == "" || e.From == "" || len(e.To) == 0 {
			return fmt.Errorf("notify.email needs host, from and to")
		}
		switch e.TLS {
		case "", "starttls", "tls", "none":
		default:
			return fmt.Errorf("notify.email.tls must be starttls, tls or none (got %q)", e.TLS)
		}
		if e.Username != "" && e.PasswordFile == "" && e.PasswordEnv == "" {
			return fmt.Errorf("notify.email: username set but no password_file or password_env")
		}
	}
	names := map[string]bool{}
	for i, w := range n.Webhooks {
		switch w.Type {
		case "generic", "slack", "discord", "teams":
		default:
			return fmt.Errorf("notify.webhooks[%d]: type must be generic, slack, discord or teams (got %q)", i, w.Type)
		}
		if w.URL == "" && w.URLFile == "" && w.URLEnv == "" {
			return fmt.Errorf("notify.webhooks[%d]: url, url_file or url_env is required", i)
		}
		name := w.Name
		if name == "" {
			name = fmt.Sprintf("%s-%d", w.Type, i)
		}
		if names[name] {
			return fmt.Errorf("notify.webhooks: duplicate name %q", name)
		}
		names[name] = true
	}
	return nil
}
