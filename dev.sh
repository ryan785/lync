#!/usr/bin/env bash
# dev.sh — sync local tree to test server, build, run, test
# usage: ./dev.sh [sync|build|run|test|lint|install|ssh|logs|pkg] [args...]
set -euo pipefail

HOST="${LYNC_HOST:?set LYNC_HOST=user@host (the test server to sync to)}"
REMOTE="${LYNC_REMOTE:-/root/lync-src}"
LOCAL="$(cd "$(dirname "$0")" && pwd)"

sync() {
  tar c --exclude=.git --exclude=bin --exclude=dist --exclude='*.rpm' --exclude='*.deb' \
      -C "$LOCAL" . \
    | ssh "$HOST" "mkdir -p $REMOTE && cd $REMOTE && tar xf -"
}

build() {
  sync
  ssh "$HOST" "cd $REMOTE && mkdir -p bin && go build -trimpath -ldflags='-s -w' -o bin/lyncd ./cmd/lyncd && go build -trimpath -ldflags='-s -w' -o bin/lync ./cmd/lync && ls -la bin/"
}

run() {
  build
  ssh "$HOST" "cd $REMOTE && ./bin/lyncd $*"
}

test_() {
  sync
  ssh "$HOST" "cd $REMOTE && go test ./..."
}

lint() {
  sync
  ssh "$HOST" "cd $REMOTE && go vet ./..."
}

install_() {
  build
  ssh "$HOST" "
    install -m755 $REMOTE/bin/lyncd /usr/sbin/lyncd
    install -m755 $REMOTE/bin/lync  /usr/bin/lync
    install -d /etc/lync /etc/lync/rules.d /var/lib/lync/feeds /var/lib/lync/reports /var/log/lync
    [ -f /etc/lync/lync.yaml ] || install -m644 $REMOTE/packaging/config/lync.yaml /etc/lync/lync.yaml
    install -m644 $REMOTE/packaging/systemd/lync.service /usr/lib/systemd/system/lync.service
    systemctl daemon-reload
    echo 'installed. enable+start: systemctl enable --now lync'
  "
}

logs() {
  ssh "$HOST" "journalctl -u lync -n ${1:-50} --no-pager"
}

ssh_() {
  ssh "$HOST" "$*"
}

pkg() {
  build
  ssh "$HOST" "cd $REMOTE && nfpm package -p rpm -f nfpm.yaml -t /tmp/ 2>&1 || echo 'nfpm not installed: run dev.sh nfpm-install'"
}

nfpm_install() {
  ssh "$HOST" '
    GOBIN=/usr/local/bin go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
  '
}

cmd="${1:-build}"; shift || true
case "$cmd" in
  sync)         sync ;;
  build)        build ;;
  run)          run "$@" ;;
  test)         test_ ;;
  lint)         lint ;;
  install)      install_ ;;
  logs)         logs "$@" ;;
  ssh)          ssh_ "$@" ;;
  pkg)          pkg ;;
  nfpm-install) nfpm_install ;;
  *) echo "usage: $0 [sync|build|run|test|lint|install|logs|ssh|pkg|nfpm-install]"; exit 1 ;;
esac
