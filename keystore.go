package authcore

// KeyStore sources authcore's cryptographic key material (the Ed25519 signing
// pair and the HMAC refresh secret).
//
// The default is disk: New generates and loads PEM files under Config.KeysDir.
// Set Config.KeyStore to override that — for example to source keys from a
// secret manager, environment variables, or KMS, which is the right fit for
// serverless or disk-averse deployments where a mounted volume is awkward.
//
// Implementations are consulted once, at New time. The returned Keys must be
// stable for the lifetime of the AuthCore instance.
//
// # Contract for custom implementations
//
// Load must return either usable material and a nil error, or a non-nil error.
// A lookup that succeeded and found nothing is an error: never return
// (nil, nil), and never return a nil pointer wrapped in a non-nil Keys, which
// is what "var k *myKeys; return k, nil" produces.
//
// New checks what Load returned before anything uses it, with the same rules
// that NewKeyStoreFromKeys applies:
//
//   - PrivateKey is ed25519.PrivateKeySize (64) bytes: the seed followed by
//     the public key that seed derives, as crypto/ed25519 produces it. A bare
//     32-byte seed is refused; expand it with ed25519.NewKeyFromSeed first.
//   - PublicKey is ed25519.PublicKeySize (32) bytes and is the public half of
//     PrivateKey.
//   - RefreshSecret is exactly 32 bytes.
//
// Material that breaks any of these makes New fail with an error that wraps
// ErrKeyManager and names the rule. New calls the accessors on the returned
// Keys for this check, so they must be safe to call as soon as Load returns.
type KeyStore interface {
	// Load returns the key material, or an error if it cannot be obtained or
	// fails validation. It never returns nil Keys together with a nil error.
	Load() (Keys, error)
}
