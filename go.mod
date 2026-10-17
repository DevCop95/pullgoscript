module github.com/DevCop95/obliteratus

// Minimum toolchain. Pinned to the newest patched 1.26.x because govulncheck
// finds reachable standard-library vulnerabilities (net, net/http, crypto/*)
// in every earlier release: 20 in 1.25/1.26.0-1.26.2 and 18 still present in
// 1.26.3. CI reads this directive via actions/setup-go's go-version-file, so
// the floor is enforced on every run.
go 1.26.9

require (
	github.com/gorilla/websocket v1.5.3
	golang.org/x/sys v0.49.0
	modernc.org/sqlite v1.60.1
)

require (
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	modernc.org/libc v1.79.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
