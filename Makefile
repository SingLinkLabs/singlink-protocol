GO ?= go
LDFLAGS_LIB = -s -w -extldflags=-Wl,-install_name,@rpath/libsinglink.dylib
export MACOSX_DEPLOYMENT_TARGET ?= 13.0

.PHONY: test cli lib linux clean

test:
	$(GO) vet ./...
	$(GO) test -race ./...

cli:
	$(GO) build -trimpath -ldflags='-s -w' -o build/singlink ./cmd/singlink

# Universal macOS library for the Flutter app.
lib:
	CGO_ENABLED=1 GOARCH=arm64 CC="clang -arch arm64" $(GO) build -trimpath -buildmode=c-shared -ldflags='$(LDFLAGS_LIB)' -o build/libsinglink-arm64.dylib ./ffi
	CGO_ENABLED=1 GOARCH=amd64 CC="clang -arch x86_64" $(GO) build -trimpath -buildmode=c-shared -ldflags='$(LDFLAGS_LIB)' -o build/libsinglink-amd64.dylib ./ffi
	lipo -create -output build/libsinglink.dylib build/libsinglink-arm64.dylib build/libsinglink-amd64.dylib
	mv build/libsinglink-arm64.h build/libsinglink.h
	rm -f build/libsinglink-arm64.dylib build/libsinglink-amd64.dylib build/libsinglink-amd64.h

# Static node binary for Linux servers.
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags='-s -w' -o build/singlink-linux-amd64 ./cmd/singlink
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags='-s -w' -o build/singlink-linux-arm64 ./cmd/singlink

clean:
	rm -rf build
