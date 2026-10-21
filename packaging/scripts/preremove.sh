#!/bin/sh
# Package pre-remove (deb prerm, rpm %preun, apk pre-deinstall).
# Stops and disables lync.service on removal; does nothing on upgrade
# (postinstall restarts the service). Never fails the transaction.

# Arguments: deb "remove" | "upgrade <new>" | ..., rpm "<count>" (0 = removal),
# apk "<old-version>" (pre-deinstall only runs on removal).
case "${1:-}" in
upgrade | failed-upgrade) exit 0 ;;
'' | *[!0-9]*) ;;
*) [ "$1" -ge 1 ] && exit 0 ;;
esac

if command -v systemctl >/dev/null 2>&1; then
	if [ -d /run/systemd/system ]; then
		systemctl stop lync.service >/dev/null 2>&1 || true
	fi
	systemctl disable lync.service >/dev/null 2>&1 || true
fi
exit 0
