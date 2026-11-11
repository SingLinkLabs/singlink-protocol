GO ?= go
LDFLAGS_LIB = -s -w -extldflags=-Wl,-install_name,@rpath/libsl3.dylib
export MACOSX_DEPLOYMENT_TARGET ?= 13.0

.PHONY: test cli lib linux clean

test:
	$(GO) vet ./...
	$(GO) test -race ./...

cli:
	$(GO) build -trimpath -ldflags='-s -w' -o build/sl3 ./cmd/sl3

# Universal macOS library for the Flutter app.
lib:
	CGO_ENABLED=1 GOARCH=arm64 CC="clang -arch arm64" $(GO) build -trimpath -buildmode=c-shared -ldflags='$(LDFLAGS_LIB)' -o build/libsl3-arm64.dylib ./ffi
	CGO_ENABLED=1 GOARCH=amd64 CC="clang -arch x86_64" $(GO) build -trimpath -buildmode=c-shared -ldflags='$(LDFLAGS_LIB)' -o build/libsl3-amd64.dylib ./ffi
	lipo -create -output build/libsl3.dylib build/libsl3-arm64.dylib build/libsl3-amd64.dylib
	mv build/libsl3-arm64.h build/libsl3.h
	rm -f build/libsl3-arm64.dylib build/libsl3-amd64.dylib build/libsl3-amd64.h

# Static node binary for Linux servers.
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags='-s -w' -o build/sl3-linux-amd64 ./cmd/sl3
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags='-s -w' -o build/sl3-linux-arm64 ./cmd/sl3

clean:
	rm -rf build
