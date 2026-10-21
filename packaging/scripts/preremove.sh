#!/bin/sh
set -e
systemctl disable --now lync >/dev/null 2>&1 || true
