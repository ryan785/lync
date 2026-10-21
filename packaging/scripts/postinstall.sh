#!/bin/sh
set -e

# Create directories the daemon expects (idempotent).
install -d -m 0755 /etc/lync /etc/lync/rules.d
install -d -m 0755 /var/lib/lync/feeds /var/lib/lync/reports
install -d -m 0755 /var/log/lync

systemctl daemon-reload >/dev/null 2>&1 || true

cat <<EOF

Lync installed.

  Start now:        systemctl enable --now lync
  Status:           lync status
  Logs:             journalctl -u lync -f
  Reports:          /var/lib/lync/reports/

EOF
