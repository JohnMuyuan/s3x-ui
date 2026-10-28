//go:build linux

package sys

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// KillStrays kills processes running a binary from dir (Xray, sbcore, mtg)
// that a previous panel left behind, and returns their names. Under systemd
// the service's cgroup goes down with the panel, but OpenRC's supervisor
// (Alpine) respawns a crashed panel while its children live on, holding the
// ports the new ones need. Call it before the panel starts any of them.
func KillStrays(dir string) []string {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	self := os.Getpid()
	var killed []string
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		exe, err := os.Readlink("/proc/" + e.Name() + "/exe")
		if err != nil {
			continue
		}
		// A binary replaced by an update reads as "<path> (deleted)".
		exe = strings.TrimSuffix(exe, " (deleted)")
		if filepath.Dir(exe) != dir {
			continue
		}
		if syscall.Kill(pid, syscall.SIGKILL) == nil {
			killed = append(killed, filepath.Base(exe))
		}
	}
	return killed
}
