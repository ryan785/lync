#!/bin/sh
# Package post-remove (deb postrm, rpm %postun, apk post-deinstall).
# Reloads systemd after the unit file is gone. Feed caches and reports in
# /var/lib/lync are kept, except on `apt-get purge` / `dpkg --purge`.
# Never fails the transaction.

# Arguments: deb "remove" | "purge" | "upgrade" | ..., rpm "<count>"
# (0 = removal), apk "<old-version>".
case "${1:-}" in
upgrade | failed-upgrade | abort-*) exit 0 ;;
purge) rm -rf /var/lib/lync /etc/lync 2>/dev/null || true ;;
'' | *[!0-9]*) ;;
*) [ "$1" -ge 1 ] && exit 0 ;;
esac

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	systemctl reset-failed lync.service >/dev/null 2>&1 || true
fi
rm -f /run/lync.sock 2>/dev/null || true
exit 0
