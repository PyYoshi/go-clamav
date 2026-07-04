package mockscan

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	clamav "github.com/PyYoshi/go-clamav"
)

// scannerMock is a hand-rolled test double. It is stdlib-only because this
// module keeps zero dependencies; the same idiom works unchanged with
// testify/mock, moq or gomock.
//
// Two rules keep test doubles honest under the fail-closed contract:
//
//  1. Never make a clean verdict the mock's default — configure it
//     explicitly per test case.
//  2. When the mock returns an error, return the zero ScanResult, exactly
//     like the real client does.
type scannerMock struct {
	res clamav.ScanResult
	err error
}

func (m scannerMock) Scan(context.Context, io.Reader) (clamav.ScanResult, error) {
	if m.err != nil {
		return clamav.ScanResult{}, m.err // zero result on error, like the real client
	}
	return m.res, nil
}

// TestUploadGate is the minimum matrix every consumer should cover:
// clean → accepted, infected → rejected, scan error → rejected.
func TestUploadGate(t *testing.T) {
	cases := []struct {
		name     string
		mock     scannerMock
		accepted bool
		wantMsg  string // substring of the rejection message
	}{
		{
			name: "clean verdict is accepted",
			mock: scannerMock{res: clamav.ScanResult{
				Verdict: clamav.VerdictClean,
				Raw:     "stream: OK",
			}},
			accepted: true,
		},
		{
			name: "detection is rejected",
			mock: scannerMock{res: clamav.ScanResult{
				Verdict:   clamav.VerdictInfected,
				Signature: "Win.Test.EICAR_HDB-1",
				Raw:       "stream: Win.Test.EICAR_HDB-1 FOUND",
			}},
			wantMsg: "Win.Test.EICAR_HDB-1",
		},
		{
			name:    "scan error is rejected (fail-closed)",
			mock:    scannerMock{err: errors.New("clamd replied ERROR")},
			wantMsg: "scan failed",
		},
		{
			name: "retryable scan error is rejected and marked for retry",
			mock: scannerMock{err: &clamav.ConnectionError{
				Op:  "dial",
				Err: errors.New("connection refused"),
			}},
			wantMsg: "retry later",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gate := &UploadGate{Scanner: tc.mock}
			err := gate.Accept(t.Context(), strings.NewReader("upload bytes"))

			if tc.accepted {
				if err != nil {
					t.Fatalf("Accept() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("Accept() = %v, want ErrRejected", err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("Accept() = %q, want substring %q", err, tc.wantMsg)
			}
		})
	}
}
