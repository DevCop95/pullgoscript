# OBLITERATUS build system
# Default target produces a console binary so `--audit` output is visible.

BINARY   := obliteratus
CMD      := ./cmd/obliteratus
LDFLAGS  := -ldflags="-s -w"

.PHONY: all build build-windowed cross audit test vet fmt clean

all: test build

build:
	@echo "[+] building windows/amd64 console binary..."
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY).exe $(CMD)

build-windowed:
	@echo "[+] building windows/amd64 windowed binary (no console)..."
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -H=windowsgui -o bin/$(BINARY).exe $(CMD)

# Cross-compile check from any host (what CI runs on Linux).
cross:
	GOOS=windows GOARCH=amd64 go build ./...

audit: build
	./bin/$(BINARY).exe --audit

test:
	gofmt -l . | (! grep .) || (gofmt -l . && false)
	go vet ./...
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin/
