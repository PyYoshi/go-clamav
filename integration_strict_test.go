//go:build integration

package clamav_test

import (
	"crypto/rand"
	"os"
	"strings"
	"testing"

	clamav "github.com/PyYoshi/go-clamav"
	"github.com/PyYoshi/go-clamav/internal/clamdtest"
)

// TestIntegrationStrict runs against the alert-enabled clamd
// (docker/clamd/clamd-strict.conf, published as CLAMAV_STRICT_TCP_ADDR).
// It pins the heuristic behaviors fail-closed callers depend on, as
// verified against ClamAV 1.4.5 and 1.5.3 on 2026-07-30:
//
//   - a real signature outranks the encrypted-entry heuristic in a mixed
//     archive while HeuristicScanPrecedence is "no" (the default);
//   - encrypted archives, broken media and exceeded limits come back as
//     Heuristics.* FOUND lines, i.e. VerdictInfected, never silent OK.
//
// Signature names are asserted by class prefix only (the last elements
// vary by format, failure mode and ClamAV version) and logged verbatim.
func strictAddr(t *testing.T) string {
	t.Helper()
	a := os.Getenv("CLAMAV_STRICT_TCP_ADDR")
	if a == "" {
		t.Skip("CLAMAV_STRICT_TCP_ADDR not set; run via `make integration`")
	}
	return a
}

func scanBytes(t *testing.T, c *clamav.Client, data []byte) clamav.ScanResult {
	t.Helper()
	res, err := c.ScanBytes(testCtx(t), data)
	if err != nil {
		t.Fatalf("ScanBytes() = %v", err)
	}
	return res
}

func wantHeuristic(t *testing.T, res clamav.ScanResult, prefix string) {
	t.Helper()
	if !res.Infected() {
		t.Fatalf("result = %+v, want infected", res)
	}
	if !strings.HasPrefix(res.Signature, prefix) {
		t.Errorf("Signature = %q, want prefix %q", res.Signature, prefix)
	}
	t.Logf("signature: %s", res.Signature)
}

func TestIntegrationStrict(t *testing.T) {
	c, err := clamav.New(strictAddr(t))
	if err != nil {
		t.Fatal(err)
	}

	encryptedBenign := clamdtest.ZipEntry{
		Name:     "benign.txt",
		Data:     []byte("harmless text behind ZipCrypto\n"),
		Password: "pass",
	}
	// Deflated so the EICAR bytes are invisible to raw byte-level
	// matching: any detection must come through the archive module,
	// which is where the precedence question lives.
	deflatedEICAR := clamdtest.ZipEntry{
		Name:    "eicar.com",
		Data:    clamdtest.EICAR(),
		Deflate: true,
	}

	t.Run("MixedArchiveSignaturePrecedence", func(t *testing.T) {
		// A mixed archive must report the malware signature, not
		// Heuristics.Encrypted.Zip, in either entry order. If this fails,
		// encrypted-entry alerts are masking real detections and callers
		// that map Heuristics.Encrypted.* to a lighter policy would
		// misclassify malware.
		for name, entries := range map[string][]clamdtest.ZipEntry{
			"encrypted-first": {encryptedBenign, deflatedEICAR},
			"eicar-first":     {deflatedEICAR, encryptedBenign},
		} {
			t.Run(name, func(t *testing.T) {
				res := scanBytes(t, c, clamdtest.BuildZip(entries...))
				if !res.Infected() {
					t.Fatalf("result = %+v, want infected", res)
				}
				if !strings.Contains(strings.ToLower(res.Signature), "eicar") {
					t.Errorf("Signature = %q, want the EICAR signature (not a heuristic)", res.Signature)
				}
				t.Logf("signature: %s", res.Signature)
			})
		}
	})

	t.Run("EncryptedZipAlert", func(t *testing.T) {
		res := scanBytes(t, c, clamdtest.BuildZip(encryptedBenign))
		wantHeuristic(t, res, "Heuristics.Encrypted.")
	})

	t.Run("FileSizeLimitAlert", func(t *testing.T) {
		// 256 KiB of random bytes exceeds MaxFileSize (128K) while staying
		// far below StreamMaxLength, so the verdict must come from
		// AlertExceedsMax, not the INSTREAM size-limit ERROR path.
		payload := make([]byte, 256<<10)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		res := scanBytes(t, c, payload)
		wantHeuristic(t, res, "Heuristics.Limits.Exceeded.")
	})

	t.Run("RecursionLimitAlert", func(t *testing.T) {
		nested := clamdtest.NestedZip(6, "inner.txt", []byte("bottom of the stack\n"))
		res := scanBytes(t, c, nested)
		wantHeuristic(t, res, "Heuristics.Limits.Exceeded.")
	})

	t.Run("RecursionWithinLimitClean", func(t *testing.T) {
		nested := clamdtest.NestedZip(2, "inner.txt", []byte("bottom of the stack\n"))
		if res := scanBytes(t, c, nested); !res.Clean() {
			t.Errorf("2-level zip = %+v, want clean", res)
		}
	})

	t.Run("BrokenPNGAlert", func(t *testing.T) {
		res := scanBytes(t, c, clamdtest.TruncatedPNG())
		wantHeuristic(t, res, "Heuristics.Broken.Media.")
	})

	t.Run("BrokenJPEGAlert", func(t *testing.T) {
		res := scanBytes(t, c, clamdtest.HeaderOnlyJPEG())
		wantHeuristic(t, res, "Heuristics.Broken.Media.")
	})

	t.Run("SmallCleanPayload", func(t *testing.T) {
		// Alerts must not fire on ordinary content within limits.
		payload := make([]byte, 64<<10)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		if res := scanBytes(t, c, payload); !res.Clean() {
			t.Errorf("64 KiB random payload = %+v, want clean", res)
		}
	})
}
