BINDIR  := bin
DISTDIR := dist
LDFLAGS := -s -w
# Release version: the git tag (v0.2.0) or `git describe` between tags.
# CI passes VERSION=<tag> explicitly. Packages use it without the "v".
VERSION ?= $(shell git describe --tags --match 'v[0-9]*' --dirty 2>/dev/null || echo v0.0.0-dev)
PKG_VERSION := $(patsubst v%,%,$(VERSION))
VERSION_LDFLAGS := -X github.com/ryan785/lync/internal/daemon.Version=$(VERSION) -X main.version=$(VERSION)

DESTDIR ?=
PREFIX  ?= /usr

RELEASE_ARCHES := amd64 arm64
PKG_FORMATS    := deb rpm apk
NFPM           ?= nfpm

.PHONY: all build test lint vet tidy clean install binaries packages package tarballs release selftest

all: build

# --- build ------------------------------------------------------------------
build:
	@mkdir -p $(BINDIR)
	go build -trimpath -ldflags='$(LDFLAGS) $(VERSION_LDFLAGS)' -o $(BINDIR)/lyncd ./cmd/lyncd
	go build -trimpath -ldflags='$(LDFLAGS) $(VERSION_LDFLAGS)' -o $(BINDIR)/lync  ./cmd/lync

# --- verify -----------------------------------------------------------------
test:
	go test ./...

lint vet:
	go vet ./...
	shellcheck -s sh install.sh run.sh lync-run tests/runner-selftest.sh packaging/scripts/*.sh

# End-to-end runner test on a Linux box (WSL is fine): fake ssh, no network.
selftest: release
	sh tests/runner-selftest.sh

tidy:
	go mod tidy

# --- install from source (developers; end users install a package) ----------
install: build
	install -Dm755 $(BINDIR)/lyncd $(DESTDIR)$(PREFIX)/sbin/lyncd
	install -Dm755 $(BINDIR)/lync  $(DESTDIR)$(PREFIX)/bin/lync
	install -Dm644 packaging/config/lync.yaml         $(DESTDIR)/etc/lync/lync.yaml
	install -Dm644 packaging/systemd/lync.service     $(DESTDIR)$(PREFIX)/lib/systemd/system/lync.service
	install -d -m 0755 $(DESTDIR)/var/lib/lync/feeds
	install -d -m 0755 $(DESTDIR)/var/lib/lync/reports

# --- release artifacts --------------------------------------------------------
# dist/ after `make release` (all listed in dist/SHA256SUMS):
#   lyncd-linux-<arch>, lync-linux-<arch>      static binaries (run.sh, lync-run)
#   lync-linux-<arch>.{deb,rpm,apk}            packages, stable names (install.sh)
#   lync_<ver>-1_<arch>.deb, lync-<ver>-1.<arch>.rpm, lync_<ver>-r1_<arch>.apk
#                                              the same packages, versioned names
#   lync-linux-<arch>.tar.gz                   binaries + config + unit (manual installs)
#   run.sh
$(DISTDIR):
	mkdir -p $(DISTDIR)

binaries: $(DISTDIR)
	@for a in $(RELEASE_ARCHES); do \
		echo "building linux/$$a $(VERSION)"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$a go build -trimpath -ldflags='$(LDFLAGS) $(VERSION_LDFLAGS)' \
			-o $(DISTDIR)/lyncd-linux-$$a ./cmd/lyncd || exit 1; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$a go build -trimpath -ldflags='$(LDFLAGS) $(VERSION_LDFLAGS)' \
			-o $(DISTDIR)/lync-linux-$$a ./cmd/lync || exit 1; \
	done

# nfpm reads LYNC_VERSION / LYNC_ARCH from the environment and the binaries
# from dist/.pkg/ (it does not expand variables in file paths; see nfpm.yaml).
packages: binaries
	@for a in $(RELEASE_ARCHES); do for f in $(PKG_FORMATS); do \
		tmp=$(DISTDIR)/.out-$$a-$$f; rm -rf $$tmp $(DISTDIR)/.pkg; mkdir -p $$tmp $(DISTDIR)/.pkg; \
		cp $(DISTDIR)/lyncd-linux-$$a $(DISTDIR)/.pkg/lyncd && cp $(DISTDIR)/lync-linux-$$a $(DISTDIR)/.pkg/lync || exit 1; \
		LYNC_VERSION=$(PKG_VERSION) LYNC_ARCH=$$a $(NFPM) package -f nfpm.yaml -p $$f -t $$tmp/ || exit 1; \
		cp $$tmp/*.$$f $(DISTDIR)/ && cp $$tmp/*.$$f $(DISTDIR)/lync-linux-$$a.$$f || exit 1; \
		rm -rf $$tmp $(DISTDIR)/.pkg; \
	done; done

package: packages

tarballs: binaries
	@for a in $(RELEASE_ARCHES); do \
		s=$(DISTDIR)/.stage-$$a; rm -rf $$s; \
		install -Dm755 $(DISTDIR)/lyncd-linux-$$a $$s/usr/sbin/lyncd && \
		install -Dm755 $(DISTDIR)/lync-linux-$$a  $$s/usr/bin/lync && \
		install -Dm644 packaging/config/lync.yaml     $$s/etc/lync/lync.yaml && \
		install -Dm644 packaging/systemd/lync.service $$s/usr/lib/systemd/system/lync.service && \
		tar -C $$s --owner=0 --group=0 --numeric-owner -czf $(DISTDIR)/lync-linux-$$a.tar.gz usr etc || exit 1; \
		rm -rf $$s; \
	done

release: binaries packages tarballs
	cp run.sh $(DISTDIR)/run.sh
	cd $(DISTDIR) && rm -f SHA256SUMS && sha256sum $$(ls | LC_ALL=C sort) > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS
	@cat $(DISTDIR)/SHA256SUMS

# --- housekeeping -----------------------------------------------------------
clean:
	rm -rf $(BINDIR) $(DISTDIR)
