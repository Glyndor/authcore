// Package layout is the vocabulary every other part of the key manager shares:
// the names and modes of the files in a key directory, the size cap on reading
// them, and the narrow logging interface the key manager depends on.
package layout

// File names written inside the key directory.
const (
	FilePrivateKey    = "ed25519_private.pem"
	FilePublicKey     = "ed25519_public.pem"
	FileRefreshSecret = "refresh_secret.key"
	FileGitignore     = ".gitignore"

	// FileMetadata records which layout wrote the key directory.
	//
	// The library allows breaking changes and ships them forward, and it persists
	// key material on disk, so a release that changes the on-disk format has to
	// migrate what is already there rather than regenerate it: regenerating
	// invalidates every refresh-token and API-key hash the consumer has stored,
	// which logs out all of their users. That migration is only possible if the
	// loader can tell what wrote the directory, which is what this file is for.
	FileMetadata = "metadata.json"

	// GitignoreContent prevents every file in the directory from being tracked.
	GitignoreContent = "# Managed by authcore — do not commit these files.\n*\n"

	// DirMode restricts the key directory to the owner only.
	DirMode = 0700

	// StagingPrefix names the staging directory entries. The dot hides them from a
	// casual listing; the prefix makes them findable for recovery and the leftover
	// scan.
	StagingPrefix = ".staging-"
)

// RefreshSecretLen is the number of raw bytes in a refresh secret.
// 32 bytes gives 256 bits of entropy, matching the HMAC-SHA256 key size.
const RefreshSecretLen = 32

// MaxKeyFileSize caps the bytes the key loader will read from disk. A healthy
// Ed25519 PEM file is ~200 bytes and a hex-encoded HMAC secret is 65 bytes,
// so 4 KiB leaves comfortable headroom for PEM comment headers without ever
// reading an oversized file. The cap protects startup from a corrupted or
// attacker-replaced key file that would otherwise be loaded whole into memory.
const MaxKeyFileSize = 4 * 1024

// Logger is the minimal logging dependency for the key manager.
// It is intentionally narrow.
// Any authcore.Logger value satisfies it via Go's structural typing.
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// KeyFileNames returns the three managed key filenames in the fixed order
// private, public, refresh secret. The slice is fresh on every call.
func KeyFileNames() []string {
	return []string{FilePrivateKey, FilePublicKey, FileRefreshSecret}
}
