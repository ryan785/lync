package daemon

import (
	"log/slog"

	"github.com/ryan785/lync/internal/config"
	"github.com/ryan785/lync/internal/notify"
)

func newNotifier(cfg *config.Config, log *slog.Logger) (scanNotifier, error) {
	n, err := notify.New(cfg.Notify, Version, log)
	if err != nil {
		return nil, err
	}
	log.Info("notifications enabled", "channels", n.Channels(), "min_severity", cfg.Notify.MinSeverity, "digest", cfg.Notify.Digest)
	return n, nil
}
