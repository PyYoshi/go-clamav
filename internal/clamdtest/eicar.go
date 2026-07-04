package clamdtest

// The EICAR anti-virus test string is deliberately split in two so the full
// 68-byte sequence never appears verbatim in the repository, in editor
// buffers, or in on-disk build artifacts — otherwise resident AV scanners
// may quarantine the checkout. The complete string only ever exists in
// memory at test runtime, which is exactly where it is needed.
const (
	eicarPart1 = `X5O!P%@AP[4\PZX54(P^)7CC)7}$`
	eicarPart2 = `EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
)

// EICAR returns the standard 68-byte EICAR anti-virus test payload. Every
// AV engine, ClamAV included, detects it by convention; the payload itself
// is inert.
func EICAR() []byte { return []byte(eicarPart1 + eicarPart2) }
