// Command basicscan scans files with clamd and prints one verdict per file.
//
// Usage:
//
//	basicscan -addr unix:///run/clamav/clamd.sock file [file...]
//
// Exit codes: 0 all clean, 1 at least one detection, 2 at least one scan
// failure (verdict unknown — under the fail-closed contract such files must
// be treated as not accepted).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	clamav "github.com/PyYoshi/go-clamav"
)

func main() {
	addr := flag.String("addr", "unix:///run/clamav/clamd.sock", "clamd address (unix:// or tcp://)")
	timeout := flag.Duration("timeout", 2*time.Minute, "per-file scan timeout")
	maxSize := flag.Int64("max-size", 25<<20, "client-side stream size limit in bytes (match clamd's StreamMaxLength)")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: basicscan [-addr ADDR] file [file...]")
		os.Exit(2)
	}

	client, err := clamav.New(*addr, clamav.WithMaxStreamSize(*maxSize))
	if err != nil {
		fmt.Fprintln(os.Stderr, "basicscan:", err)
		os.Exit(2)
	}

	exit := 0
	for _, path := range flag.Args() {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		res, err := client.ScanFile(ctx, path)
		cancel()
		switch {
		case err != nil:
			// Unknown verdict: report as a failure, never as clean.
			fmt.Printf("%s: UNKNOWN (%v)\n", path, err)
			exit = max(exit, 2)
		case res.Infected():
			fmt.Printf("%s: INFECTED (%s)\n", path, res.Signature)
			exit = max(exit, 1)
		case res.Clean():
			fmt.Printf("%s: clean\n", path)
		default:
			// Unreachable under the library contract; fail-closed backstop.
			fmt.Printf("%s: UNKNOWN (indeterminate verdict)\n", path)
			exit = max(exit, 2)
		}
	}
	os.Exit(exit)
}
