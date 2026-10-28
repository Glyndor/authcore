//go:build !windows

package fileio

// retryOpen runs op once. Only Windows reports a file that another handle
// holds as a transient open failure; elsewhere an open that fails has failed.
func retryOpen(op func() error) error {
	return op()
}
