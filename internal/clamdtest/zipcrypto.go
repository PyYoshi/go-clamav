package clamdtest

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"hash/crc32"
	"math"
)

// u16 and u32 convert sample sizes for zip header fields, panicking on
// overflow instead of truncating. Sample builders never approach these
// bounds; the guard keeps a future mistake loud instead of corrupting
// the archive silently.
func u16(n int) uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic("clamdtest: value does not fit in uint16")
	}
	return uint16(n) // #nosec G115 -- bounds checked above
}

func u32(n int) uint32 {
	if n < 0 || int64(n) > math.MaxUint32 {
		panic("clamdtest: value does not fit in uint32")
	}
	return uint32(n) // #nosec G115 -- bounds checked above
}

// ZipEntry describes one file inside an archive built by BuildZip.
type ZipEntry struct {
	// Name is the entry's path inside the archive.
	Name string
	// Data is the uncompressed entry content.
	Data []byte
	// Password, when non-empty, encrypts the entry with the legacy PKWARE
	// "ZipCrypto" scheme (store method only). The scheme is
	// cryptographically broken and is used solely so clamd classifies the
	// entry as encrypted (Heuristics.Encrypted.Zip).
	Password string
	// Deflate compresses the entry (plaintext entries only). A deflated
	// entry is invisible to raw byte-level signature matching, so its
	// detection must go through clamd's archive module — which is exactly
	// what the archive-behavior integration tests need to exercise.
	Deflate bool
}

// BuildZip assembles a ZIP archive from the given entries, in memory.
//
// It is hand-rolled because archive/zip cannot write encrypted entries and
// the zero-dependency policy (ADR-0003) rules out external zip libraries.
// Only what the integration tests need is implemented: store and raw-deflate
// methods, optional ZipCrypto encryption, no zip64. Round-trip through
// archive/zip (including keystream decryption of encrypted entries) is
// covered by unit tests; acceptance by unzip and 7z was verified manually
// during the 2026-07-30 clamd behavior verification.
//
// BuildZip panics on an entry that is both encrypted and deflated; the
// harness never needs that combination.
func BuildZip(entries ...ZipEntry) []byte {
	var body, central bytes.Buffer
	le := binary.LittleEndian

	for _, e := range entries {
		crc := crc32.ChecksumIEEE(e.Data)
		var flags, method uint16
		var comp []byte

		switch {
		case e.Password != "":
			if e.Deflate {
				panic("clamdtest.BuildZip: encrypted+deflated entries are not supported")
			}
			flags = 0x0001 // bit 0: encrypted
			method = 0     // store
			zc := newZipCrypto(e.Password)
			// 12-byte encryption header: 11 arbitrary bytes, then the high
			// byte of the CRC (flag bit 3 unset selects the CRC check byte).
			hdr := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, byte((crc >> 24) & 0xff)}
			comp = zc.encrypt(append(hdr, e.Data...))
		case e.Deflate:
			method = 8
			var b bytes.Buffer
			fw, err := flate.NewWriter(&b, flate.BestCompression)
			if err != nil {
				panic(err)
			}
			if _, err := fw.Write(e.Data); err != nil {
				panic(err)
			}
			if err := fw.Close(); err != nil {
				panic(err)
			}
			comp = b.Bytes()
		default:
			method = 0
			comp = e.Data
		}

		offset := u32(body.Len())
		name := []byte(e.Name)

		local := make([]byte, 30)
		le.PutUint32(local[0:], 0x04034b50)
		le.PutUint16(local[4:], 20) // version needed to extract
		le.PutUint16(local[6:], flags)
		le.PutUint16(local[8:], method)
		le.PutUint16(local[10:], 0)    // mod time
		le.PutUint16(local[12:], 0x21) // mod date (1980-01-01)
		le.PutUint32(local[14:], crc)
		le.PutUint32(local[18:], u32(len(comp)))
		le.PutUint32(local[22:], u32(len(e.Data)))
		le.PutUint16(local[26:], u16(len(name)))
		le.PutUint16(local[28:], 0) // extra length
		body.Write(local)
		body.Write(name)
		body.Write(comp)

		cd := make([]byte, 46)
		le.PutUint32(cd[0:], 0x02014b50)
		le.PutUint16(cd[4:], 20) // version made by
		le.PutUint16(cd[6:], 20) // version needed to extract
		le.PutUint16(cd[8:], flags)
		le.PutUint16(cd[10:], method)
		le.PutUint16(cd[12:], 0)
		le.PutUint16(cd[14:], 0x21)
		le.PutUint32(cd[16:], crc)
		le.PutUint32(cd[20:], u32(len(comp)))
		le.PutUint32(cd[24:], u32(len(e.Data)))
		le.PutUint16(cd[28:], u16(len(name)))
		// Extra, comment, disk, and attribute fields stay zero.
		le.PutUint32(cd[42:], offset)
		central.Write(cd)
		central.Write(name)
	}

	eocd := make([]byte, 22)
	le.PutUint32(eocd[0:], 0x06054b50)
	le.PutUint16(eocd[8:], u16(len(entries)))
	le.PutUint16(eocd[10:], u16(len(entries)))
	le.PutUint32(eocd[12:], u32(central.Len()))
	le.PutUint32(eocd[16:], u32(body.Len()))

	out := make([]byte, 0, body.Len()+central.Len()+len(eocd))
	out = append(out, body.Bytes()...)
	out = append(out, central.Bytes()...)
	out = append(out, eocd...)
	return out
}

// zipCrypto holds the three rolling keys of the PKWARE traditional cipher
// (APPNOTE.TXT §6.1). Encryption and decryption share the same keystream.
type zipCrypto struct{ k0, k1, k2 uint32 }

func newZipCrypto(password string) *zipCrypto {
	z := &zipCrypto{0x12345678, 0x23456789, 0x34567890}
	for i := range len(password) {
		z.update(password[i])
	}
	return z
}

func crcShift(crc uint32, b byte) uint32 {
	return crc32.IEEETable[byte(crc&0xff)^b] ^ (crc >> 8)
}

func (z *zipCrypto) update(plain byte) {
	z.k0 = crcShift(z.k0, plain)
	z.k1 = (z.k1+(z.k0&0xff))*134775813 + 1
	z.k2 = crcShift(z.k2, byte((z.k1>>24)&0xff))
}

func (z *zipCrypto) streamByte() byte {
	t := (z.k2 & 0xffff) | 2
	return byte(((t * (t ^ 1)) >> 8) & 0xff)
}

func (z *zipCrypto) encrypt(plain []byte) []byte {
	out := make([]byte, len(plain))
	for i, p := range plain {
		out[i] = p ^ z.streamByte()
		z.update(p)
	}
	return out
}

// decrypt reverses encrypt; the keystream is keyed by plaintext, so the
// XOR must happen before the key update. Used by the round-trip tests.
func (z *zipCrypto) decrypt(cipher []byte) []byte {
	out := make([]byte, len(cipher))
	for i, c := range cipher {
		p := c ^ z.streamByte()
		z.update(p)
		out[i] = p
	}
	return out
}
