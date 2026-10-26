package hostiletest

import (
	"encoding/base64"
	"fmt"

	"github.com/Glyndor/authcore/auth/password"
	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Enc returns n zero bytes in the unpadded standard base64 the module writes.
func Enc(n int) string { return base64.RawStdEncoding.EncodeToString(make([]byte, n)) }

// Relaxed returns a low cost config with no composition rules and the given maximum length.
func Relaxed(maxLen int) password.Config {
	cfg := LowCost()
	cfg.MinLength, cfg.MaxLength = 8, maxLen
	cfg.RequireUpper, cfg.RequireLower = password.Bool(false), password.Bool(false)
	cfg.RequireDigit, cfg.RequireSymbol = password.Bool(false), password.Bool(false)
	return cfg
}

// RefHash writes the PHC string for plaintext under the given cost and salt,
// the way every Argon2 implementation does.
func RefHash(plaintext string, m, t uint32, p uint8, salt []byte) string {
	key := argon2.IDKey([]byte(norm.NFC.String(plaintext)), salt, t, m, p, 32)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, t, p, b64.EncodeToString(salt), b64.EncodeToString(key))
}
