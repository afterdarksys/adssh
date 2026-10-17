//go:build !linux

package sys

// SetNonDumpable is a no-op where the dumpable flag does not exist.
func SetNonDumpable() error { return nil }
