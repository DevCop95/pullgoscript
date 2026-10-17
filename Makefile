# OBLITERATUS build system
# Default target produces a console binary so `--audit` output is visible.

BINARY   := obliteratus
CMD      := ./cmd/obliteratus
LDFLAGS  := -ldflags="-s -w"

.PHONY: all build build-windowed cross audit test vet fmt clean sast fuzz-check cover

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

# Static analysis, mirroring the `sast` job in CI: same exclusions, same
# rationale (see .github/workflows/ci.yml). Requires: go install
# github.com/securego/gosec/v2/cmd/gosec@latest
sast:
	gosec -exclude=G103,G104 ./...

# Short fuzz smoke over the parser targets. CI runs 30s each; this is the
# "did I break a parser" check. A crasher lands in testdata/fuzz/<target>/.
fuzz-check:
	go test -run='^$$' -fuzz=FuzzRegf -fuzztime=20s ./internal/audit
	go test -run='^$$' -fuzz=FuzzParseRep -fuzztime=20s ./internal/krb
	go test -run='^$$' -fuzz=FuzzUnpack -fuzztime=20s ./internal/research
	go test -run='^$$' -fuzz=FuzzMaskRoundTrip -fuzztime=20s ./internal/obfuscate
	go test -run='^$$' -fuzz=FuzzSanitizeName -fuzztime=20s ./internal/persist

# Whole-tree statement coverage; CI fails below its ratcheting floor.
cover:
	go test ./... -coverprofile=cover.out -count=1
	go tool cover -func=cover.out | tail -1

fmt:
	gofmt -w .

clean:
	rm -rf bin/
