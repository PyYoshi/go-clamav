package clamdtest

import (
	"archive/zip"
	"bytes"
	"io"
	"testing"
)

func readZip(t *testing.T, data []byte) *zip.Reader {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("archive/zip rejected BuildZip output: %v", err)
	}
	return zr
}

func TestBuildZipPlainRoundTrip(t *testing.T) {
	want := []byte("plain entry content\n")
	zr := readZip(t, BuildZip(ZipEntry{Name: "a.txt", Data: want}))
	if len(zr.File) != 1 {
		t.Fatalf("entries = %d, want 1", len(zr.File))
	}
	f := zr.File[0]
	if f.Name != "a.txt" {
		t.Errorf("name = %q, want a.txt", f.Name)
	}
	rc, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("content = %q, want %q", got, want)
	}
}

func TestBuildZipDeflateRoundTrip(t *testing.T) {
	want := bytes.Repeat([]byte("compress me "), 512)
	built := BuildZip(ZipEntry{Name: "big.txt", Data: want, Deflate: true})
	if len(built) >= len(want) {
		t.Errorf("deflated archive (%d bytes) not smaller than content (%d bytes)", len(built), len(want))
	}
	zr := readZip(t, built)
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("deflated content does not round-trip")
	}
}

func TestBuildZipEncryptedEntry(t *testing.T) {
	plain := []byte("secret but harmless payload\n")
	zr := readZip(t, BuildZip(ZipEntry{Name: "enc.txt", Data: plain, Password: "pass"}))
	f := zr.File[0]

	if f.Flags&0x0001 == 0 {
		t.Fatal("encryption flag (bit 0) not set")
	}

	// archive/zip cannot decrypt ZipCrypto; pull the raw stored bytes and
	// decrypt with the same keystream to prove the cipher is well-formed.
	raw, err := f.OpenRaw()
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := io.ReadAll(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cipher) != len(plain)+12 {
		t.Fatalf("stored size = %d, want %d (12-byte header + data)", len(cipher), len(plain)+12)
	}

	zc := newZipCrypto("pass")
	dec := zc.decrypt(cipher)
	if dec[11] != byte(f.CRC32>>24) {
		t.Errorf("check byte = %#x, want high CRC byte %#x", dec[11], byte(f.CRC32>>24))
	}
	if !bytes.Equal(dec[12:], plain) {
		t.Error("decrypted content does not match plaintext")
	}

	// A wrong password must not produce the plaintext.
	zc = newZipCrypto("wrong")
	if bytes.Equal(zc.decrypt(cipher)[12:], plain) {
		t.Error("wrong password still decrypted the entry")
	}
}

func TestBuildZipMixedEntries(t *testing.T) {
	zr := readZip(t, BuildZip(
		ZipEntry{Name: "enc.txt", Data: []byte("hidden"), Password: "pass"},
		ZipEntry{Name: "plain.txt", Data: []byte("visible"), Deflate: true},
	))
	if len(zr.File) != 2 {
		t.Fatalf("entries = %d, want 2", len(zr.File))
	}
	if zr.File[0].Flags&1 != 1 || zr.File[1].Flags&1 != 0 {
		t.Errorf("encryption flags = [%d, %d], want [1, 0]",
			zr.File[0].Flags&1, zr.File[1].Flags&1)
	}
}

func TestBuildZipEncryptedDeflatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("BuildZip did not panic on encrypted+deflated entry")
		}
	}()
	BuildZip(ZipEntry{Name: "x", Data: []byte("x"), Password: "p", Deflate: true})
}

func TestNestedZip(t *testing.T) {
	want := []byte("innermost")
	data := NestedZip(3, "inner.txt", want)
	for range 3 {
		zr := readZip(t, data)
		if len(zr.File) != 1 {
			t.Fatalf("entries = %d, want 1", len(zr.File))
		}
		rc, err := zr.File[0].Open()
		if err != nil {
			t.Fatal(err)
		}
		next, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		if err := rc.Close(); err != nil {
			t.Fatal(err)
		}
		data = next
	}
	if !bytes.Equal(data, want) {
		t.Errorf("after unwrapping 3 layers got %q, want %q", data, want)
	}
}
