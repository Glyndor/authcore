package field

import "errors"

// Sentinel errors returned by the field package.
// Use errors.Is to check for these in calling code.
var (
	// ErrInvalidConfig is returned by New when the provided Config fails
	// validation (today: an empty Context). Empty is refused because
	// Context is not decoration: it is bound into both the AES additional
	// authenticated data and the blind index, so a caller who does not
	// name the field is telling the module nothing, and silently
	// accepting "" would make every field share one keyspace.
	//
	// Safety: INTERNAL — a startup/programming error. Treat as a 500.
	ErrInvalidConfig = errors.New("field: invalid configuration")

	// ErrDecrypt is returned by Decrypt for every failure mode: an
	// input shorter than the nonce, an input that is not valid base64,
	// and a failed GCM authentication tag. The three are not
	// distinguished, because which one failed is information about the
	// stored data and the caller has nothing useful to do differently.
	// A row that does not decrypt is corrupt or never belonged to this
	// column, and the response is the same either way.
	//
	// Safety: CLIENT-SAFE — the caller may surface a generic error
	// ("could not read this row") to the user. Do not echo the input
	// back, and do not log enough to recreate the ciphertext.
	ErrDecrypt = errors.New("field: decryption failed")
)
