# OBLITERATUS - Build System (Orchestrator)
# Objective: Minimal Signature Production and Cross-Platform Synthesis

BINARY_NAME=obliteratus
SRC_GO=./src/go
SRC_C=./src/c

# Compilation Flags:
# -s: Omit symbol table and debug information.
# -w: Omit DWARF symbol table.
# These flags reduce the binary size and complexity, maintaining 'Low Signal Profile'.
LDFLAGS=-ldflags="-s -w"

all: build-windows

build-windows:
	@echo "[+] Synthesizing Windows Binary (Grade S)..."
	@# Go automatically integrates .s files in the same package.
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build $(LDFLAGS) -o bin/$(BINARY_NAME).exe $(SRC_GO)/*.go

clean:
	@echo "[-] Cleaning Workspace..."
	rm -rf bin/

.PHONY: all build-windows build-linux clean
