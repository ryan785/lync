#!/bin/sh
# apk post-upgrade: restart lync.service if systemd runs it. Alpine normally
# has no systemd, in which case there is nothing to restart. Never fails.
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	systemctl try-restart lync.service >/dev/null 2>&1 || true
fi
exit 0
