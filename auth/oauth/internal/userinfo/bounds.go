package userinfo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// profileMaxTokens caps the JSON tokens (values, keys and brackets) of a
	// profile. Real profiles carry a few dozen; the cap keeps a body made only
	// of the shortest values from decoding into millions of allocations.
	profileMaxTokens = 1 << 14
	// profileMaxDepth caps how deeply a profile may nest.
	profileMaxDepth = 32
)

// errTooLarge marks a body that exceeds the structure bounds.
var errTooLarge = errors.New("profile has too many values or nests too deeply")

// checkShape walks body token by token, without building values, and refuses
// it once it passes the token or depth bound. The walk costs a fraction of
// decoding the same body, and it stops at the bound, so a hostile body is
// rejected before the decoder allocates anything for it. Syntax errors are
// left to the decode that follows, except that the walk ends where the first
// value does, so the caller can check what trails it.
func checkShape(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	depth := 0
	for n := 1; ; n++ {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return nil // malformed: Decode reports it with its own message
		}
		if n > profileMaxTokens {
			return fmt.Errorf("%w (more than %d tokens)", errTooLarge, profileMaxTokens)
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
				if depth > profileMaxDepth {
					return fmt.Errorf("%w (deeper than %d levels)", errTooLarge, profileMaxDepth)
				}
			default:
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}
