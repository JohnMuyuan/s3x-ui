//go:build !linux

package sys

// KillStrays is Linux only.
func KillStrays(dir string) []string {
	return nil
}
