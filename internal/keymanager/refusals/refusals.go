// Package refusals builds the errors the key manager returns when it declines
// to touch a key directory. Their wording is a contract: an operator who reaches
// one must be told how to recover without being advised to delete key files,
// which since auth/field shipped is the advice that destroys every encrypted
// column.
package refusals

import (
	"fmt"
	"strings"

	"github.com/Glyndor/authcore/internal/keymanager/fsguard"
)

// TwoInits reports that the directory holds material from two different
// initialisations and refuses to write or delete anything.
func TwoInits(dir, name string) error {
	return fmt.Errorf(
		"key directory %q holds %s from two different initialisations; "+
			"the published bytes do not match the staged bytes; "+
			"refusing to write or delete any further files in this directory; "+
			"the .staging-* directory next to them holds the set that was being "+
			"published, so decide which %s is the genuine one before removing either",
		dir, name, name)
}

// Inconsistent is the message returned when a partial set has no
// matching staging directory. It must NOT contain the phrase "delete all key
// files", which since auth/field shipped is the advice that destroys every
// encrypted column.
func Inconsistent(dir string) error {
	present, missing := fsguard.PresentAndMissing(dir)
	return fmt.Errorf(
		"key directory %q is in an inconsistent state: present {%s}, missing {%s}; "+
			"restore the missing file(s) from a backup; refresh_secret.key must "+
			"not be deleted or regenerated because every stored refresh-token "+
			"hash, API-key hash and every auth/field encrypted column depends on it",
		dir, strings.Join(present, ", "), strings.Join(missing, ", "))
}

// Regeneration is the message returned when metadata.json records a key
// set and none of its files remain. Like Inconsistent it must not advise
// deleting key files; deleting metadata.json is named as the deliberate way to
// start over, since that is the only file whose loss costs nothing.
func Regeneration(dir, keyID string) error {
	return fmt.Errorf(
		"key directory %q held a key set (metadata.json records key id %q) and none of its files remain; "+
			"restore them from a backup. Generating a new set would invalidate every issued token, "+
			"every stored refresh-token and API-key hash and every auth/field encrypted column; "+
			"to start over with new keys on purpose, delete metadata.json",
		dir, keyID)
}

// SecretMismatch reports a refresh secret that is not the one recorded for the
// key pair in the directory. The advice never asks for a key file to be
// deleted: the secret that belongs to these keys is in a backup, and replacing
// it on purpose is a one-line edit of the descriptor.
func SecretMismatch(dir string) error {
	return fmt.Errorf(
		"key directory %q holds a refresh_secret.key that does not belong to its key pair "+
			"(metadata.json records a different binding); restore the refresh_secret.key "+
			"that was generated with these keys. Starting with another secret would leave every "+
			"stored refresh-token and API-key hash unverifiable and every auth/field encrypted "+
			"column unreadable; to adopt the current secret on purpose, remove the "+
			"secret_binding line from metadata.json",
		dir)
}

// WaitTimeout builds the message the spec calls for: another initialiser
// started publishing and did not finish within the wait, names what is on
// disk, and points at a restart. It never mentions symlinks.
func WaitTimeout(dir string) error {
	present, missing := fsguard.PresentAndMissing(dir)
	presentStr := "none"
	if len(present) > 0 {
		presentStr = strings.Join(present, ", ")
	}
	missingStr := "none"
	if len(missing) > 0 {
		missingStr = strings.Join(missing, ", ")
	}
	return fmt.Errorf(
		"another initialiser started publishing keys in %q and did not finish "+
			"within the wait: present {%s}, missing {%s}; "+
			"a restart finishes it when the staging directory is still there",
		dir, presentStr, missingStr)
}

// SymlinkTarget returns the same refusal createExclusive returns today
// when the destination is a symlink. The text is the contract: an operator
// who reaches this must not be told to delete all key files, which since
// auth/field shipped is the advice that destroys every encrypted column.
func SymlinkTarget(dst string, linkErr error) error {
	return fmt.Errorf(
		"refusing to write %q: something already exists there. If it is a "+
			"symlink, authcore never writes key material through one: remove it "+
			"and let authcore create the file, or point KeysDir at the real "+
			"directory: %w", dst, linkErr)
}

// NoHardLinks reports a filesystem that cannot give the hard-link
// guarantee authcore needs to publish keys safely. If the caller had already
// published the private key, the staging directory is preserved so a helper
// can recover through it; otherwise it is removed.
func NoHardLinks(dir, name string, keepStaging bool, linkErr error) error {
	keep := ""
	if keepStaging {
		keep = "; the staging directory has been kept as recovery material"
	}
	return fmt.Errorf(
		"filesystem under %q does not support hard links, which authcore "+
			"needs to create keys safely (%s): %w%s; create the keys once on a "+
			"local filesystem and mount them, or supply them through Config.KeyStore",
		dir, name, linkErr, keep)
}

// MissingDir returns the message a load-only deploy should see when dir
// is unreachable. The wording names the path and the three files a complete
// set has, and is what an operator running `podman volume ls` next needs to
// read.
func MissingDir(dir string) error {
	return fmt.Errorf(
		"key directory %q does not exist; authcore will not generate keys in "+
			"load-only mode. Provision ed25519_private.pem, ed25519_public.pem "+
			"and refresh_secret.key (restore them from a backup, or generate "+
			"them once without Config.RequireExistingKeys set) before starting",
		dir)
}

// IncompleteLoad reports a KeysDir that does not hold all three key
// files. The wording lists present and missing files, tells the operator to
// restore the missing ones from a backup, and repeats why refresh_secret.key
// must not be regenerated: deleting or regenerating it invalidates every
// stored refresh-token hash, API-key hash and auth/field column.
func IncompleteLoad(dir string, present, missing []string) error {
	presentStr := "none"
	if len(present) > 0 {
		presentStr = strings.Join(present, ", ")
	}
	missingStr := "none"
	if len(missing) > 0 {
		missingStr = strings.Join(missing, ", ")
	}
	return fmt.Errorf(
		"key directory %q is not complete in load-only mode: present {%s}, missing {%s}; "+
			"restore the missing file(s) from a backup; refresh_secret.key must "+
			"not be regenerated because every stored refresh-token hash, "+
			"API-key hash and every auth/field encrypted column depends on it",
		dir, presentStr, missingStr)
}
