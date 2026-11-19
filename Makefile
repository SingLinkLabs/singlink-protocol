GO ?= go
# Release builds use at least the toolchain named in go.mod. The go command
# switches to it automatically unless GOTOOLCHAIN is set to local or path;
# check-go refuses an older toolchain in that case.
RELEASE_GO := $(shell sed -n 's/^toolchain go//p' go.mod)
GOVULNCHECK_VERSION := v1.10.0
LDFLAGS_LIB = -s -w -extldflags=-Wl,-install_name,@rpath/libsinglink.dylib
export MACOSX_DEPLOYMENT_TARGET ?= 13.0

.PHONY: test cli lib linux clean check-go vulncheck

test:
	$(GO) vet ./...
	$(GO) test -race ./...

# Fails when the Go toolchain in use is older than the release toolchain.
check-go:
	@v="$$($(GO) env GOVERSION)"; v="$${v#go}"; v="$${v%% *}"; \
	case "$$v" in [0-9]*) ;; *) echo "release builds need a released Go >= $(RELEASE_GO), found $$v" >&2; exit 1 ;; esac; \
	if [ -z "$(RELEASE_GO)" ] || [ "$$(printf '%s\n%s\n' "$(RELEASE_GO)" "$$v" | sort -V | head -n 1)" != "$(RELEASE_GO)" ]; then \
		echo "release builds need Go >= $(RELEASE_GO), found go$$v (run with GOTOOLCHAIN=go$(RELEASE_GO))" >&2; exit 1; \
	fi

# Known vulnerabilities reachable from this module, including the standard
# library of the toolchain in use; exits non-zero when any is found.
vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

cli: check-go
	$(GO) build -trimpath -ldflags='-s -w' -o build/singlink ./cmd/singlink

# Universal macOS library for the Flutter app.
lib: check-go
	CGO_ENABLED=1 GOARCH=arm64 CC="clang -arch arm64" $(GO) build -trimpath -buildmode=c-shared -ldflags='$(LDFLAGS_LIB)' -o build/libsinglink-arm64.dylib ./ffi
	CGO_ENABLED=1 GOARCH=amd64 CC="clang -arch x86_64" $(GO) build -trimpath -buildmode=c-shared -ldflags='$(LDFLAGS_LIB)' -o build/libsinglink-amd64.dylib ./ffi
	lipo -create -output build/libsinglink.dylib build/libsinglink-arm64.dylib build/libsinglink-amd64.dylib
	mv build/libsinglink-arm64.h build/libsinglink.h
	rm -f build/libsinglink-arm64.dylib build/libsinglink-amd64.dylib build/libsinglink-amd64.h

# Static node binary for Linux servers.
linux: check-go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags='-s -w' -o build/singlink-linux-amd64 ./cmd/singlink
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags='-s -w' -o build/singlink-linux-arm64 ./cmd/singlink

clean:
	rm -rf build
