package clamdtest

import (
	"bytes"
	"image/png"
	"testing"
)

func TestTruncatedPNG(t *testing.T) {
	full := validPNG()
	if _, err := png.Decode(bytes.NewReader(full)); err != nil {
		t.Fatalf("base image is not a valid PNG: %v", err)
	}

	cut := TruncatedPNG()
	if !bytes.HasPrefix(cut, []byte("\x89PNG\r\n\x1a\n")) {
		t.Error("truncated PNG lost its signature")
	}
	if len(cut) >= len(full) {
		t.Errorf("truncated length %d not shorter than full %d", len(cut), len(full))
	}
	if _, err := png.Decode(bytes.NewReader(cut)); err == nil {
		t.Error("truncated PNG still decodes; expected mid-stream cut")
	}
}

func TestHeaderOnlyJPEG(t *testing.T) {
	j := HeaderOnlyJPEG()
	if !bytes.HasPrefix(j, []byte{0xff, 0xd8, 0xff, 0xe0}) {
		t.Error("missing SOI/APP0 header")
	}
	if bytes.HasSuffix(j, []byte{0xff, 0xd9}) {
		t.Error("unexpected EOI marker; sample must stay unterminated")
	}
}
