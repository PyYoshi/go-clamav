package clamdtest

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
)

// Benign sample builders for the archive/heuristic integration tests.
// Everything here is harmless content assembled at run time — nothing that
// resident antivirus could object to is ever written to the repository.

// NestedZip wraps data in depth layers of store-method zips. With depth
// above clamd's MaxRecursion the scan is flagged (AlertExceedsMax) or
// silently truncated (default config).
func NestedZip(depth int, name string, data []byte) []byte {
	cur := BuildZip(ZipEntry{Name: name, Data: data})
	for i := 1; i < depth; i++ {
		cur = BuildZip(ZipEntry{Name: fmt.Sprintf("level%d.zip", i), Data: cur})
	}
	return cur
}

// TruncatedPNG returns the first 60% of a valid PNG image: an intact
// signature and IHDR with the pixel stream cut mid-chunk. clamd flags it
// as Heuristics.Broken.Media.PNG.* when AlertBrokenMedia is enabled.
func TruncatedPNG() []byte {
	full := validPNG()
	return full[:len(full)*60/100]
}

func validPNG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := range 64 {
		for x := range 64 {
			img.Set(x, y, color.RGBA{R: uint8(x * 4), G: uint8(y * 4), B: 0x7f, A: 0xff})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// HeaderOnlyJPEG returns a well-formed SOI/JFIF header followed by filler
// bytes with no scan data and no EOI marker. clamd flags it as
// Heuristics.Broken.Media.JPEG.* when AlertBrokenMedia is enabled.
func HeaderOnlyJPEG() []byte {
	header := []byte{
		0xff, 0xd8, // SOI
		0xff, 0xe0, 0x00, 0x10, // APP0, length 16
		'J', 'F', 'I', 'F', 0x00,
		0x01, 0x01, // version 1.1
		0x00,                   // aspect-ratio units
		0x00, 0x01, 0x00, 0x01, // density 1x1
		0x00, 0x00, // no thumbnail
	}
	return append(header, bytes.Repeat([]byte{0xaa}, 4096)...)
}
