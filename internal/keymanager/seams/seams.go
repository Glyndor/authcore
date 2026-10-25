// Package seams holds the hooks the key manager's tests use to make the
// filesystem misbehave: a crash at a named point of the publish transaction,
// and a hard-link call that fails on demand.
//
// Production code must leave every hook at its default. They live in one
// package because more than one part of the key manager consults the same
// hook, and a test has to be able to reach it from outside.
package seams

import "os"

// LinkFile is the os.Link call, exposed as a variable so a test can simulate a
// filesystem that does not support hard links. Production callers must leave it
// pointing at os.Link; nothing else is portable.
var LinkFile = os.Link

// FaultAt is a test seam. When a test sets it to return a non-nil error at one
// of the named points, the publish transaction aborts at that point WITHOUT
// cleaning up, leaving the disk in the state a process crash would leave it in.
//
// Valid points:
//
//	"staged"             staging directory created and synced, no link attempted yet
//	"published-private"  ed25519_private.pem hard-linked into KeysDir
//	"published-public"   ed25519_public.pem hard-linked into KeysDir
//	"published-secret"   refresh_secret.key hard-linked into KeysDir
//	"metadata-before-rename"  metadata temp file written, not yet renamed.
//	                       Only reachable by calling writeMetadata directly;
//	                       through New, syncMetadata treats a metadata write
//	                       failure as a warning by design.
//	"metadata-written"   metadata.json atomically replaced
//
// Production callers must leave it returning nil at every point.
var FaultAt = func(point string) error { return nil }

// Fault consults FaultAt for point. Call sites use it so they never read the
// variable directly.
func Fault(point string) error { return FaultAt(point) }

// AfterKeyRead is a test seam for the stability check of keyload.Files. It is
// called once the file with the given index (0 private key, 1 public key,
// 2 refresh secret) has been read in the given attempt, before the next file
// is opened and before any path is looked at again. A test uses it to replace
// the key set at an exact point of the read, which a timing race can only hit
// by chance. Production callers must leave it nil.
var AfterKeyRead func(attempt, file int)
