BINDIR  := bin
DISTDIR := dist
LDFLAGS := -s -w
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)

DESTDIR ?=
PREFIX  ?= /usr

.PHONY: all build test lint vet tidy clean install rpm deb package release selftest

all: build

# --- build ------------------------------------------------------------------
build:
	@mkdir -p $(BINDIR)
	go build -trimpath -ldflags='$(LDFLAGS)' -o $(BINDIR)/lyncd ./cmd/lyncd
	go build -trimpath -ldflags='$(LDFLAGS)' -o $(BINDIR)/lync  ./cmd/lync

# --- verify -----------------------------------------------------------------
test:
	go test ./...

lint vet:
	go vet ./...
	shellcheck -s sh run.sh lync-run tests/runner-selftest.sh

# End-to-end runner test on a Linux box (WSL is fine): fake ssh, no network.
selftest: release
	sh tests/runner-selftest.sh

tidy:
	go mod tidy

# --- install (manual; package managers below are preferred) ----------------
install: build
	install -Dm755 $(BINDIR)/lyncd $(DESTDIR)$(PREFIX)/sbin/lyncd
	install -Dm755 $(BINDIR)/lync  $(DESTDIR)$(PREFIX)/bin/lync
	install -Dm644 packaging/config/lync.yaml         $(DESTDIR)/etc/lync/lync.yaml
	install -Dm644 packaging/systemd/lync.service     $(DESTDIR)$(PREFIX)/lib/systemd/system/lync.service
	install -d -m 0755 $(DESTDIR)/etc/lync/rules.d
	install -d -m 0755 $(DESTDIR)/var/lib/lync/feeds
	install -d -m 0755 $(DESTDIR)/var/lib/lync/reports
	install -d -m 0755 $(DESTDIR)/var/log/lync

# --- packaging --------------------------------------------------------------
$(DISTDIR):
	mkdir -p $(DISTDIR)

rpm: build $(DISTDIR)
	nfpm package -p rpm -f nfpm.yaml -t $(DISTDIR)/

deb: build $(DISTDIR)
	nfpm package -p deb -f nfpm.yaml -t $(DISTDIR)/

package: rpm deb

# --- release: static linux binaries + SHA256SUMS for run.sh / lync-run -------
RELEASE_ARCHES := amd64 arm64

release: $(DISTDIR)
	@for a in $(RELEASE_ARCHES); do \
		echo "building linux/$$a"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$a go build -trimpath \
			-ldflags='$(LDFLAGS) -X github.com/ryan785/lync/internal/daemon.Version=$(VERSION)' \
			-o $(DISTDIR)/lyncd-linux-$$a ./cmd/lyncd || exit 1; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$a go build -trimpath -ldflags='$(LDFLAGS)' \
			-o $(DISTDIR)/lync-linux-$$a ./cmd/lync || exit 1; \
	done
	cp run.sh $(DISTDIR)/run.sh
	cd $(DISTDIR) && sha256sum lyncd-linux-* lync-linux-* run.sh > SHA256SUMS
	@cat $(DISTDIR)/SHA256SUMS

# --- housekeeping -----------------------------------------------------------
clean:
	rm -rf $(BINDIR) $(DISTDIR)
