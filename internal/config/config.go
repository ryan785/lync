package config

import (
	"fmt"
	"os"
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
}

type FeedConfig struct {
	SyncInterval time.Duration   `yaml:"sync_interval"`
	CacheDir     string          `yaml:"cache_dir"`
	Sources      []FeedSourceCfg `yaml:"sources"`
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
		Scan: ScanConfig{Interval: 24 * time.Hour, OnStart: false},
		Feed: FeedConfig{
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
	// Unknown feed source names and rules levels are deliberately tolerated
	// (feed.Build skips them; rules.ParseLevel falls back to medium) so a
	// config typo degrades coverage instead of taking the daemon down.
	return nil
}
