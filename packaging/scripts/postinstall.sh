#!/bin/sh
# Package post-install (deb postinst, rpm %post, apk post-install).
#
# Fresh install: enable and start lync.service when systemd is running.
# Upgrade: restart the service if it was enabled or running.
# Without systemd (containers, WSL, Alpine/OpenRC): print how to run it.
# Never fails the package transaction.

# Arguments: deb "configure <old-version>" (old empty on first install),
# rpm "<count>" (1 = install, >=2 = upgrade), apk "<new-version>".
action=install
case "${1:-}" in
configure) [ -n "${2:-}" ] && action=upgrade ;;
abort-*) exit 0 ;;
'' | *[!0-9]*) ;;
*) [ "$1" -ge 2 ] && action=upgrade ;;
esac

mkdir -p /etc/lync /var/lib/lync/feeds /var/lib/lync/reports 2>/dev/null || true

if [ ! -d /run/systemd/system ]; then
	# Not booted with systemd. Enabling still works offline (image builds,
	# chroots) so the service starts on the next systemd boot.
	if [ "$action" = install ] && command -v systemctl >/dev/null 2>&1; then
		systemctl enable lync.service >/dev/null 2>&1 || true
	fi
	echo "lync: systemd is not running here; start the daemon with '/usr/sbin/lyncd &' or run a single scan with 'lyncd -once'."
	exit 0
fi

systemctl daemon-reload >/dev/null 2>&1 || true

if [ "$action" = upgrade ]; then
	if systemctl is-enabled --quiet lync.service 2>/dev/null ||
		systemctl is-active --quiet lync.service 2>/dev/null; then
		systemctl restart lync.service >/dev/null 2>&1 ||
			echo "lync: restart failed; see 'journalctl -u lync -n 50 --no-pager'."
	fi
	exit 0
fi

systemctl enable lync.service >/dev/null 2>&1 || true
if systemctl start lync.service >/dev/null 2>&1; then
	echo "lync: service started. Status: 'lync status'; logs: 'journalctl -u lync -f'; reports: /var/lib/lync/reports/"
else
	echo "lync: the service did not start; see 'systemctl status lync' and 'journalctl -u lync -n 50 --no-pager'."
fi
exit 0
