package loadonly_test

import "github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"

// The tests in this package were written against keymanager.New and
// keymanager.Load and keep reading the same way: these aliases point at the
// test-side stand-in for the facade, which calls the sub-packages the facade
// itself delegates to.
type KeyManager = bootstraptest.KeyManager

var (
	// New is keymanager.New without the wrapper; it seeds a directory.
	New = bootstraptest.New
	// Load is keymanager.Load without the wrapper.
	Load = bootstraptest.Load
)
